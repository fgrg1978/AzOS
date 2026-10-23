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
//! - **Report**: one `[HWBUS]` line per outcome, the introspection tree's
//!   `devices/` (Kconfig INSPECT), and the
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
const RECORD_ONLY: [&str; 9] =
    ["uart", "intc", "pci-host", "ramfb", "fb-simple", "soc", "ccache", "riscv-iommu", "smmuv3"];

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
// arch-only: the Raspberry Pi mailbox and PM block (aarch64) are the only callers that are neither a vf2 nor a K1.
#[cfg(any(
    feature = "vf2",
    feature = "k1",
    feature = "wdt-sbsa",
    feature = "i2c-dw",
    all(feature = "soc-k1", feature = "thermal"),
    all(feature = "rpi-firmware", target_arch = "aarch64"),
    all(feature = "wdt-bcm2835-pm", target_arch = "aarch64")
))]
fn map_window(dev: &Device) -> Result<usize, ProbeError> {
    map_reg(dev, dev.base, dev.size)
}

/// Map one register window of `dev` (`base`, `size`): see [`map_window`].
// arch-only: as `map_window`.
#[cfg(any(
    feature = "vf2",
    feature = "k1",
    feature = "wdt-sbsa",
    all(feature = "soc-k1", feature = "thermal"),
    all(feature = "rpi-firmware", target_arch = "aarch64"),
    all(feature = "wdt-bcm2835-pm", target_arch = "aarch64")
))]
fn map_reg(dev: &Device, base: u64, size: u64) -> Result<usize, ProbeError> {
    let (base, size) = (base as usize, size as usize);
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

/// The rate in Hz the tree states for the clock `sel` of node `n`, for a
/// provider the SoC frameworks do not model: the `assigned-clock-rates` cell
/// of the `assigned-clocks` entry that is the same clock, on the consumer's
/// node or on the provider's (the RP1's clock block assigns its own `clk_sys`),
/// else the `clock-frequency` of a `fixed-clock` provider. What the SoC bind
/// would have set had the provider modelled the clock.
#[cfg(all(any(feature = "vf2", feature = "i2c-dw"), feature = "soc"))]
fn tree_clock_rate(fdt: &azos_soc::Fdt<'_>, n: azos_soc::NodeId, sel: azos_soc::consumer::Sel<'_>) -> Option<u64> {
    use azos_soc::consumer;
    let want = consumer::lookup(fdt, n, "clocks", "clock-names", "#clock-cells", sel).ok()?;
    let assigned = |at: azos_soc::NodeId| -> Option<u64> {
        let rates = fdt.prop(at, "assigned-clock-rates")?;
        (0..consumer::count(fdt, at, "assigned-clocks", "#clock-cells").ok()?).find_map(|i| {
            let e = consumer::slot(fdt, at, "assigned-clocks", "#clock-cells", i).ok()??;
            (e.provider == want.provider && e.spec == want.spec)
                .then(|| azos_soc::fdt::cell(rates, i))
                .flatten()
                .filter(|&hz| hz != 0)
                .map(u64::from)
        })
    };
    let fixed = || {
        fdt.is_compatible(want.provider, "fixed-clock")
            .then(|| fdt.prop(want.provider, "clock-frequency").and_then(|v| azos_soc::fdt::cell(v, 0)))
            .flatten()
            .filter(|&hz| hz != 0)
            .map(u64::from)
    };
    assigned(n).or_else(|| assigned(want.provider)).or_else(fixed)
}

/// What the tree says of a DesignWare I2C node's timing: its clock's rate
/// (the clock framework's when it models the clock, else [`tree_clock_rate`];
/// the JH7110 provider's table has no I2C APB clock, `soc/src/jh7110/clk.rs`,
/// the RP1's has no provider at all), `clock-frequency` (the bus rate) and
/// the I2C binding's fall and hold times. A node outside the tree, or no SoC
/// frameworks: nothing but the defaults, and the controller's own counts are
/// kept (`i2c_dw::Counts::Kept`).
#[cfg(feature = "i2c-dw")]
fn dw_i2c_timing(dev: &Device) -> azos_drv_bus::i2c_dw::Timing {
    use azos_drv_bus::i2c_dw::Timing;
    #[cfg(feature = "soc")]
    if let Some(node) = dev.dt_node {
        let facts = super::soc::with(|fdt, soc, bus, _| {
            use azos_drv_bus::i2c_dw::DEFAULT_BUS_HZ;
            use azos_soc::consumer::Sel;
            let n = azos_soc::NodeId(node);
            let cell = |name: &str| fdt.prop(n, name).and_then(|v| azos_soc::fdt::cell(v, 0));
            let live = soc.clocks.get(fdt, n, Sel::Index(0)).ok().and_then(|c| soc.clocks.rate(bus, c).ok());
            Timing {
                ic_clk_hz: live.or_else(|| tree_clock_rate(fdt, n, Sel::Index(0))),
                bus_hz: cell("clock-frequency").unwrap_or(DEFAULT_BUS_HZ),
                scl_fall_ns: cell("i2c-scl-falling-time-ns"),
                sda_fall_ns: cell("i2c-sda-falling-time-ns"),
                sda_hold_ns: cell("i2c-sda-hold-time-ns"),
            }
        });
        if let Some(t) = facts {
            return t;
        }
    }
    let _ = dev;
    Timing::with_clock(None)
}

/// An I2C controller node of the tree, its window mapped at `base`: a
/// DesignWare one with its node's timing facts (`dw_i2c_timing`), a K1 one
/// recorded by window for the PMIC's bus (`I2C_WINDOWS`).
#[cfg(any(feature = "i2c-dw", feature = "k1"))]
fn attach_i2c_node(dev: &Device, base: usize) -> Result<(), ProbeError> {
    #[cfg(feature = "i2c-dw")]
    let cfg = dw_i2c_timing(dev);
    #[cfg(feature = "k1")]
    let cfg = azos_drv_bus::i2c::BusConfig;
    let _bus = attach_i2c(dev.name.as_str(), dev.base, base, &cfg)?;
    #[cfg(all(feature = "k1", feature = "soc"))]
    if let Some(w) = I2C_WINDOWS.get(_bus as usize) {
        w.store(dev.base as usize, core::sync::atomic::Ordering::Release);
    }
    Ok(())
}

/// An I2C controller, its window mapped at `base`, to the driver with what
/// the binding knows of it (`timing`; the K1 takes nothing), and the boot
/// line that says which bus it became.
#[cfg(any(feature = "i2c-dw", feature = "k1"))]
fn attach_i2c(name: &str, phys: u64, base: usize, cfg: &azos_drv_bus::i2c::BusConfig) -> Result<u8, ProbeError> {
    use azos_drv_bus::i2c::AttachError;
    match azos_drv_bus::i2c::i2c_attach(base, cfg) {
        Ok((bus, found)) => {
            #[cfg(feature = "i2c-dw")]
            {
                use azos_drv_bus::i2c_dw::{Counts, Mode};
                let khz = match found.mode { Mode::Standard => 100, Mode::Fast => 400, Mode::FastPlus => 1000 };
                let fifo = if found.depth_from_ip { "" } else { " (Kconfig: the IP reports none)" };
                match (found.counts, cfg.ic_clk_hz) {
                    (Counts::Computed, Some(hz)) => kprintln!(
                        "[I2C] bus {} on {} ({:#x}): DesignWare {:#x}, {} kHz, ic_clk {} kHz, SCL counts {}/{}, RX FIFO {}{}",
                        bus, name, phys, found.version, khz, hz / 1000, found.hcnt, found.lcnt, found.rx_depth, fifo),
                    _ => kprintln!(
                        "[I2C] bus {} on {} ({:#x}): DesignWare {:#x}, {} kHz, ic_clk unknown: SCL counts {}/{} kept, RX FIFO {}{}",
                        bus, name, phys, found.version, khz, found.hcnt, found.lcnt, found.rx_depth, fifo),
                }
            }
            #[cfg(feature = "k1")]
            {
                let () = found;
                kprintln!("[I2C] bus {} on {} ({:#x})", bus, name, phys);
            }
            Ok(bus)
        }
        Err(AttachError::Taken) => Err(ProbeError::Busy),
        Err(AttachError::Refused(e)) => {
            azos_drv_sys::kerr!("[I2C] {} ({:#x}) not driven: {:?}", name, phys, e);
            Err(ProbeError::Failed)
        }
    }
}

/// A device-tree watchdog: the VF2's WDT-L or an SBSA Generic Watchdog,
/// whichever the node's `compatible` names (the id table bound only the ones
/// this image compiles).
fn attach_wdt(dev: &Device) -> Result<(), ProbeError> {
    #[cfg(feature = "vf2")]
    if dev.compatible().any(|c| c == "starfive,jh7110-wdt") {
        return azos_drv_sys::wdt::wdt_attach(map_window(dev)?).map_err(|_| ProbeError::Busy);
    }
    #[cfg(feature = "wdt-sbsa")]
    if dev.compatible().any(|c| c == "arm,sbsa-gwdt") {
        use azos_drv_sys::wdt_sbsa::FRAME_BYTES;
        let Some((rbase, rsize)) = dev.reg2 else {
            azos_drv_sys::kerr!("[WDT] {}: arm,sbsa-gwdt without a refresh frame (second reg)", dev.name.as_str());
            return Err(ProbeError::Failed);
        };
        if dev.size < FRAME_BYTES || rsize < FRAME_BYTES {
            return Err(ProbeError::Failed);
        }
        let (ctrl, refresh) = (map_window(dev)?, map_reg(dev, rbase, rsize)?);
        let v = azos_drv_sys::wdt::sbsa_attach(ctrl, refresh).map_err(|_| ProbeError::Busy)?;
        kprintln!("[WDT] SBSA generic watchdog: control {:#x}, refresh {:#x}, architecture version {}",
                  dev.base, rbase, v);
        return Ok(());
    }
    let _ = dev;
    Err(ProbeError::NoSuchDriver)
}

/// The AMD FCH watchdog behind the SMBus function `vendor:device` at
/// `revision` (the PCI bring-up's `wdt` probe): a layout this driver knows,
/// the PM window mapped and the watchdog's decode turned on, then its window
/// mapped and handed over (`azos_drv_sys::wdt_sp5100`).
#[cfg(feature = "wdt-sp5100")]
pub(crate) fn attach_sp5100(vendor: u16, device: u16, revision: u8) -> Result<(), ProbeError> {
    use azos_drv_sys::wdt_sp5100 as t;
    if !t::is_efch_mmio(vendor, device, revision) {
        kprintln!("[WDT] FCH {:04x}:{:04x} rev {:#04x}: not the Zen layout, watchdog not driven",
                  vendor, device, revision);
        return Err(ProbeError::NoSuchDriver);
    }
    let map = |phys: u64, len: u64| {
        if super::map_mmio_region(phys as usize, len as usize) { Ok(phys as usize) } else { Err(ProbeError::Failed) }
    };
    let pm = map(t::PM_PHYS, t::PM_BYTES)?;
    if let Err(e) = azos_drv_sys::wdt::sp5100_decode(pm) {
        azos_drv_sys::kerr!("[WDT] FCH watchdog: {:?}", e);
        return Err(ProbeError::Failed);
    }
    let wdt = map(t::WDT_PHYS, t::WDT_BYTES)?;
    match azos_drv_sys::wdt::sp5100_attach(pm, wdt) {
        Ok(fired) => {
            kprintln!("[WDT] AMD FCH watchdog at {:#x}{}", t::WDT_PHYS,
                      if fired { "; the last reset was the watchdog's" } else { "" });
            Ok(())
        }
        Err(t::Refused::Busy) => Err(ProbeError::Busy),
        Err(e) => {
            azos_drv_sys::kerr!("[WDT] FCH watchdog: {:?}", e);
            Err(ProbeError::Failed)
        }
    }
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
        (fdt.prop(n, "non-removable").is_some(), cell("fifo-depth"), live.or_else(|| tree_clock_rate(fdt, n, azos_soc::consumer::Sel::Name("ciu"))))
    });
    // Without the SoC frameworks (Kconfig SOC_FRAMEWORKS, on by default for
    // this board) there is no tree to read the facts from.
    // The node is still required (no node: no such driver), only not read.
    #[cfg(not(feature = "soc"))]
    let _ = node;
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

/// The GPIO controller: its window and interrupt line to the driver, then
/// what the tree says about its input pins (`describe_gpio_keys`).
#[cfg(any(feature = "vf2", feature = "k1"))]
fn attach_gpio(dev: &Device) -> Result<(), ProbeError> {
    azos_drv_gpio::gpio::gpio_attach(map_window(dev)?, dev.irq).map_err(|_| ProbeError::Busy)?;
    #[cfg(feature = "soc")]
    if let Some(node) = dev.dt_node {
        describe_gpio_keys(node);
    }
    Ok(())
}

/// Every `gpio-keys` child (the Linux binding: `gpios`, `debounce-interval`)
/// whose `gpios` names the controller at `node`, recorded with the driver
/// (`gpio_describe_key`): the kill switch takes its line's polarity and
/// debounce window from there. The specifier's length is the controller's
/// `#gpio-cells` and the driver decodes it (`gpio_specifier`), so no board's
/// layout is assumed here. Without the SoC frameworks there is no tree to
/// read, and no pin is described.
#[cfg(all(feature = "soc", any(feature = "vf2", feature = "k1")))]
fn describe_gpio_keys(node: u32) {
    use azos_drv_gpio::gpio::{self, KeyLine};
    let mut described = 0u32;
    super::soc::with(|fdt, _, _, _| {
        let ctrl = azos_soc::NodeId(node);
        let Some(ncells) = fdt.u32_prop(ctrl, "#gpio-cells").map(|n| n as usize) else { return };
        if ncells == 0 || ncells > 4 {
            return;
        }
        fdt.walk(|keys| {
            if !fdt.is_compatible(keys, "gpio-keys") || !fdt.is_available(keys) {
                return;
            }
            for child in fdt.children(keys) {
                let Some(v) = fdt.prop(child, "gpios") else { continue };
                let Some(ph) = azos_soc::fdt::cell(v, 0) else { continue };
                if fdt.by_phandle(ph) != Some(ctrl) {
                    continue;
                }
                let mut cells = [0u32; 4];
                if (0..ncells).any(|i| azos_soc::fdt::cell(v, 1 + i).map(|c| cells[i] = c).is_none()) {
                    continue;
                }
                let Some((pin, flags)) = gpio::gpio_specifier(&cells[..ncells]) else { continue };
                let key = KeyLine {
                    active_low: flags & gpio::GPIO_ACTIVE_LOW != 0,
                    debounce_ms: fdt.u32_prop(child, "debounce-interval")
                        .unwrap_or(gpio::GPIO_KEYS_DEBOUNCE_MS_DEFAULT),
                };
                if gpio::gpio_describe_key(pin, key) {
                    described += 1;
                }
            }
        });
    });
    if described > 0 {
        kprintln!("[GPIO] {} input line(s) described by the tree (gpio-keys)", described);
    }
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

/// The input clock of an Intel LPSS I2C function, by the driver name its PCI
/// id carries in `hwbus.ids` (the Linux `intel-lpss-pci.c` platform info the
/// id names): Sunrise Point's 120 MHz, Cannon Lake's (and Comet Lake's)
/// 216 MHz.
#[cfg(all(feature = "i2c-dw", feature = "pci"))]
fn lpss_ic_clk_hz(driver: &str) -> Option<u64> {
    match driver {
        "i2c-lpss-spt" => Some(120_000_000),
        "i2c-lpss-cnl" => Some(216_000_000),
        _ => None,
    }
}

/// An Intel LPSS I2C function: its BAR 0 mapped (`map_bars`, as the other PCI
/// drivers), the LPSS private registers checked to name an I2C and the
/// function released from reset (`i2c_dw::lpss_release`), then the DesignWare
/// controller at the BAR's start attached as the next bus, at the clock the
/// id names and the I2C binding's defaults (100 kHz): an ACPI companion's
/// timing (`SSCN`/`FMCN`) and its devices' rates need the DSDT, which the
/// kernel does not read. Polled by the `i2c-svc` task; the function's
/// interrupt is not routed.
#[cfg(all(feature = "i2c-dw", feature = "pci"))]
pub(crate) fn attach_lpss_i2c<C: azos_pci::ConfigSpace>(
    driver: &str,
    dev: &Device,
    cfg: &mut C,
    f: &azos_pci::FunctionInfo,
    window: &mut azos_pci::BarWindow,
) -> Result<(), ProbeError> {
    use azos_drv_bus::i2c_dw::Timing;
    let Some(clk) = lpss_ic_clk_hz(driver) else { return Err(ProbeError::NoSuchDriver) };
    let bars = azos_drv_virtio::virtio::pci::msix_selftest::map_bars(cfg, f, window).map_err(|e| {
        azos_drv_sys::kerr!("[I2C] LPSS {} not driven: {:?}", f.bdf, e);
        ProbeError::Failed
    })?;
    let base = bars[0];
    if base == 0 {
        azos_drv_sys::kerr!("[I2C] LPSS {} not driven: BAR 0 is not a memory BAR", f.bdf);
        return Err(ProbeError::Failed);
    }
    if let Err(ty) = azos_drv_bus::i2c::i2c_lpss_release(base) {
        azos_drv_sys::kerr!("[I2C] LPSS {} not driven: its CAPS name type {}, not an I2C", f.bdf, ty);
        return Err(ProbeError::Failed);
    }
    attach_i2c(dev.name.as_str(), base as u64, base, &Timing::with_clock(Some(clk))).map(|_| ())
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
            "gpio" => attach_gpio(dev),
            #[cfg(any(feature = "vf2", feature = "k1"))]
            "pwm" => azos_drv_actuator::pwm::pwm_attach(map_window(dev)?).map_err(|_| ProbeError::Busy),
            // The watchdogs: a device-tree node here, the AMD FCH's SMBus
            // function through the PCI bring-up (it reads the revision).
            "wdt" => match dev.kind {
                #[cfg(feature = "wdt-sp5100")]
                hwbus::BusKind::Pci => match self.pci.as_mut() {
                    Some(p) => p.probe(driver, dev),
                    None => Err(ProbeError::Failed),
                },
                _ => attach_wdt(dev),
            },
            // arch-only: the BCM2835 PM block is the Raspberry Pis', and the Pis are aarch64.
            #[cfg(all(feature = "wdt-bcm2835-pm", target_arch = "aarch64"))]
            "pm-wdt" => {
                if dev.size < azos_drv_power::bcm2835_pm::MIN_WINDOW {
                    return Err(ProbeError::Failed);
                }
                crate::entry::aarch64::ext::rpi_pm::attach(map_window(dev)?).map_err(|_| ProbeError::Busy)
            }
            #[cfg(feature = "vf2")]
            "dmac" => azos_drv_dmac::dma::dma_attach(map_window(dev)?).map_err(|_| ProbeError::Busy),
            #[cfg(feature = "vf2")]
            "dw-mshc" => attach_dwmshc(dev),
            // One probe per controller the tree enables; the bus number is
            // the order they bind in (`i2c_attach`). A DesignWare node brings
            // its timing facts (`dw_i2c_timing`).
            #[cfg(any(feature = "i2c-dw", feature = "k1"))]
            "i2c" => attach_i2c_node(dev, map_window(dev)?),
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
            #[cfg(all(feature = "rpi-firmware", target_arch = "aarch64"))]
            "rpi-mbox" => {
                crate::entry::aarch64::ext::rpi_mbox::attach(map_window(dev)?);
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
            "nvme" | "ahci" | "virtio-net-pci" | "virtio-gpu-pci" | "virtio-snd-pci" | "e1000e" | "igc" | "rp1"
            | "i2c-lpss-spt" | "i2c-lpss-cnl" => match self.pci.as_mut() {
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
            // A DesignWare USB 2.0 core (the Raspberry Pi's): device tree only.
            #[cfg(feature = "usb-dwc2")]
            "dwc2" => super::usb::attach_dwc2(dev),
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

/// Does the machine have QEMU `virt`'s virtio-mmio windows? Yes when the
/// device tree names a `virtio,mmio` node, or there is no tree (an ELF boot,
/// x86_64's PVH start): `false` only for a tree that describes a machine
/// without them (a Raspberry Pi 3 has RAM where QEMU `virt` puts them).
/// Set by [`note_firmware_virtio`] before the windows are mapped.
#[cfg(not(any(feature = "vf2", feature = "k1")))]
pub(crate) fn virtio_mmio_windows_exist() -> bool {
    VIRTIO_IN_TREE.load(core::sync::atomic::Ordering::Relaxed)
}

#[cfg(not(any(feature = "vf2", feature = "k1")))]
static VIRTIO_IN_TREE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(true);

/// Record from the tree at `dtb_ptr` (a physical address; 0: none) whether it
/// names a `virtio,mmio` node ([`virtio_mmio_windows_exist`]). Once, before the
/// late windows are mapped.
#[cfg(not(any(feature = "vf2", feature = "k1")))]
pub(crate) fn note_firmware_virtio(dtb_ptr: usize) {
    // arch-only: x86_64's firmware table is no device tree.
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
    let _ = dtb_ptr;
    #[cfg(any(target_arch = "riscv64", target_arch = "aarch64"))]
    if dtb_ptr != 0 {
        let mut named = false;
        let blob = azos_mm::addr::phys_to_virt(dtb_ptr) as *const u8;
        // SAFETY: the firmware's tree, which `early_main` parsed; every read is
        // bounded by its header.
        let walked = unsafe {
            azos_dtb::dtb_devices(blob, &mut |d: &azos_dtb::DtDevice<'_>| {
                named |= d.compatible.split(|&b| b == 0).any(|c| c == b"virtio,mmio");
            })
        };
        if walked.is_some() {
            VIRTIO_IN_TREE.store(named, core::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Enumerate what the firmware describes: the device tree's nodes (riscv64,
/// aarch64) and the populated virtio-mmio windows, then bind the kernel's own
/// hardware among them. Call after the late MMIO windows are mapped.
pub(crate) fn enumerate_firmware(dtb_ptr: usize) {
    // The USB probes read `dr_mode` of a DWC3 or DWC2 node from the tree.
    #[cfg(feature = "usb-hc")]
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
                    .with_reg2(d.reg2)
                    .with_dma_mask(d.dma_mask)
                    .with_dma_offset(d.dma_offset)
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
        // A tree that names no virtio-mmio node has no such window to read.
        let slots = if virtio_mmio_windows_exist() { VIRTIO_MMIO_COUNT } else { 0 };
        for slot in 0..slots {
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

/// The driver the native table gives PCI function `f`, if any: the one place
/// PCI ids are written is `crates/drivers/*/hwbus.ids`, so the diagnostics
/// and the IOMMU setup that need "the NIC" or "a function with no driver"
/// ask the table rather than repeat `0x1af4:0x1041`.
#[cfg(feature = "pci")]
pub(crate) fn driver_of(f: &azos_pci::FunctionInfo) -> Option<&'static str> {
    let d = Device::pci(hwbus::PciId {
        bus: f.bdf.bus,
        device: f.bdf.device,
        function: f.bdf.function,
        vendor: f.vendor,
        device_id: f.device,
        class: f.class,
    });
    match hwbus::natural(&d, NATIVE, &[]) {
        Some(Choice::Native(n)) => Some(n),
        _ => None,
    }
}

/// The first function of `funcs` the native table gives to `driver`.
#[cfg(feature = "pci")]
pub(crate) fn function_for<'a>(
    driver: &str,
    funcs: &'a [Option<azos_pci::FunctionInfo>],
) -> Option<&'a azos_pci::FunctionInfo> {
    funcs.iter().flatten().find(|f| driver_of(f) == Some(driver))
}

/// The register window (base, size) of the first device-tree device the
/// native table gives to `driver`: hardware a boot step drives outside the
/// bus (the SMMU) is found through its id line, not a second `compatible`.
#[cfg(feature = "iommu-smmuv3")]
pub(crate) fn window_for(driver: &str) -> Option<(u64, u64)> {
    hwbus::with(|bus| {
        bus.iter()
            .find(|(_, s)| matches!(hwbus::natural(&s.dev, NATIVE, &[]), Some(Choice::Native(n)) if n == driver))
            .map(|(_, s)| (s.dev.base, s.dev.size))
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
    bind(&["gpio", "wdt", "pm-wdt"]);
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

// ── The introspection tree: devices/ ────────────────────────────────────

/// A device's `state` word.
#[cfg(feature = "inspect")]
fn state_name(s: State) -> &'static str {
    match s {
        State::Free => "free",
        State::Detected => "detected",
        State::Probing => "probing",
        State::Bound => "bound",
        State::ProbeFailed => "probe-failed",
        State::Unbound => "unbound",
        State::NotAdmitted => "not-admitted",
        State::Unmatched => "unmatched",
    }
}

/// The `state` and `driver` nodes of each device the tree lists, by handle.
#[cfg(feature = "inspect")]
static TREE: azos_sync::SpinLock<[Option<(u32, azos_inspect::NodeId, azos_inspect::NodeId)>; hwbus::MAX_DEVICES]> =
    azos_sync::SpinLock::new([None; hwbus::MAX_DEVICES]);

/// Text of up to 48 bytes, made in place.
#[cfg(feature = "inspect")]
#[derive(Clone, Copy)]
struct Short {
    b: [u8; 48],
    n: usize,
}

#[cfg(feature = "inspect")]
impl core::fmt::Write for Short {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let s = s.as_bytes();
        if self.n + s.len() > self.b.len() {
            return Err(core::fmt::Error);
        }
        self.b[self.n..self.n + s.len()].copy_from_slice(s);
        self.n += s.len();
        Ok(())
    }
}

#[cfg(feature = "inspect")]
impl Short {
    fn of(v: impl core::fmt::Display) -> Short {
        let mut s = Short { b: [0; 48], n: 0 };
        let _ = write!(s, "{}", v);
        s
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.b[..self.n]).unwrap_or("?")
    }
}

/// `devices/<handle>/{name, identity, state, driver, base, size, irq}`, one
/// directory per device the bus holds when the tree is built: the handle is
/// what `DOMAIN_MMIO_MAP` takes, the identity says what the device is
/// (`pci:1af4:1041`, `dt:ns16550a`, `virtio:2`). `state` and `driver` are
/// rewritten at each refresh.
#[cfg(feature = "inspect")]
pub(crate) fn inspect_build(
    b: &mut azos_inspect::Builder<'_, '_>,
    root: azos_inspect::NodeId,
) -> Result<(), azos_inspect::Error> {
    struct Dev {
        h: u32,
        name: Short,
        ident: Short,
        base: u64,
        size: u64,
        irq: u32,
    }
    // Copied out under the bus lock (a short hold), built after.
    let mut devs: [Option<Dev>; hwbus::MAX_DEVICES] = [const { None }; hwbus::MAX_DEVICES];
    hwbus::with(|bus| {
        for ((h, s), slot) in bus.iter().zip(devs.iter_mut()) {
            *slot = Some(Dev {
                h: h.0,
                name: Short::of(s.dev.name.as_str()),
                ident: Short::of(Ident(&s.dev)),
                base: s.dev.base,
                size: s.dev.size,
                irq: s.dev.irq,
            });
        }
    });
    let dir = b.dir(root, "devices")?;
    let mut ids = [None; hwbus::MAX_DEVICES];
    let mut r = Ok(());
    for (d, slot) in devs.iter().flatten().zip(ids.iter_mut()) {
        let one = |b: &mut azos_inspect::Builder<'_, '_>| {
            let n = b.dir(dir, Short::of(d.h).as_str())?;
            b.string(n, "name", d.name.n.max(1), d.name.as_str())?;
            b.string(n, "identity", d.ident.n.max(1), d.ident.as_str())?;
            let state = b.string(n, "state", 12, "")?;
            let driver = b.string(n, "driver", 24, "")?;
            b.u64(n, "base", d.base)?;
            b.u64(n, "size", d.size)?;
            b.u64(n, "irq", d.irq as u64)?;
            Ok((d.h, state, driver))
        };
        match one(b) {
            Ok(v) => *slot = Some(v),
            Err(e) => {
                r = Err(e);
                break;
            }
        }
    }
    *TREE.lock_irqsave() = ids;
    r
}

/// Rewrite each listed device's `state` and `driver`; the values that were
/// not published.
#[cfg(feature = "inspect")]
pub(crate) fn inspect_refresh(w: &azos_inspect::Writer<'_>) -> u32 {
    let ids = *TREE.lock_irqsave();
    let mut now = [None; hwbus::MAX_DEVICES];
    hwbus::with(|bus| {
        for (h, s) in bus.iter() {
            if let Some(i) = ids.iter().position(|x| x.is_some_and(|(k, ..)| k == h.0)) {
                now[i] = Some((state_name(s.state), Short::of(binding_name(&s.binding))));
            }
        }
    });
    let mut bad = 0;
    for (id, cur) in ids.iter().zip(now.iter()) {
        let (Some((_, state, driver)), Some((st, drv))) = (id, cur) else { continue };
        bad += w.set_str(*state, st).is_err() as u32;
        bad += w.set_str(*driver, drv.as_str()).is_err() as u32;
    }
    bad
}

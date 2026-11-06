// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's driver records: one per driver the image's id table names.
//!
//! The ids are `azos_hwbus::DRIVERS`, generated from the `hwbus.ids` files;
//! [`RECORDS`] pairs each with the kernel's ops for it, through
//! `native_drivers!`, so the table is built from the generated list: a driver
//! whose ids are in the image and whose ops are not here does not compile,
//! and an ops const no driver names is dead code. Every bind, unbind and
//! system suspend of a kernel-driven device goes through a record
//! (`boot::hwbus`).
//!
//! The environment ([`KernelEnv`]) lends what a probe needs besides the
//! device (the PCI bring-up's configuration space for the stage that binds
//! PCI drivers) and keeps the books an unbind is checked against: the
//! interrupt line, DMA and register window each device holds,
//! and, for a line the IRQ thread serves, the line binding itself.

use azos_drv_bus::hwbus::{self, Device, Env, Handle, Held, Host, Op, Ops, Power, ProbeError, Record, Unbind};
use azos_sync::SpinLock;


/// The kernel as a driver host.
pub(crate) struct Kernel;

impl Host for Kernel {
    type Env<'a> = KernelEnv<'a>;
}

/// What a kernel op is lent for one bind.
pub(crate) struct KernelEnv<'a> {
    #[cfg(feature = "pci")]
    pub(crate) pci: Option<&'a mut dyn super::hwbus::PciProbe>,
    #[cfg(not(feature = "pci"))]
    pub(crate) pci: core::marker::PhantomData<&'a ()>,
}

impl KernelEnv<'_> {
    /// No PCI configuration space lent: the stages that bind no PCI driver.
    pub(crate) fn plain() -> Self {
        #[cfg(feature = "pci")]
        return KernelEnv { pci: None };
        #[cfg(not(feature = "pci"))]
        KernelEnv { pci: core::marker::PhantomData }
    }

    /// The PCI function `dev` is, with the configuration space and BAR
    /// window the bring-up lent: `Failed` outside the PCI stage.
    #[cfg(feature = "pci")]
    fn pci_fn(&mut self, dev: &Device) -> Result<super::hwbus::PciFn<'_>, ProbeError> {
        self.pci.as_mut().and_then(|p| p.function(dev)).ok_or(ProbeError::Failed)
    }
}

/// What each device holds, by handle: written by the ops that take and give
/// back an interrupt line, DMA or a window.
static HELD: SpinLock<[Held; hwbus::MAX_DEVICES]> = SpinLock::new([Held::NONE; hwbus::MAX_DEVICES]);

/// Change what device `h` holds.
pub(crate) fn hold(h: Handle, f: impl FnOnce(&mut Held)) {
    if let Some(held) = HELD.lock().get_mut(h.index()) {
        f(held);
    }
}

/// The context each device's booked line was enabled on (`blk_irq::line_target`).
static LINE_TARGET: SpinLock<[u32; hwbus::MAX_DEVICES]> = SpinLock::new([0; hwbus::MAX_DEVICES]);

/// Book `line`, enabled on context `target`, to device `h`.
pub(crate) fn hold_line(h: Handle, line: u32, target: u32) {
    hold(h, |held| held.irq = Some(line));
    if let Some(t) = LINE_TARGET.lock().get_mut(h.index()) {
        *t = target;
    }
}

/// Device `h` as a class registry names it: its handle and the occupancy of
/// its slot (`azos_drv_base::instances::DeviceId`). The bus lock is taken from
/// a driver op, which the bus calls with it released.
#[cfg(feature = "gpio-soft-expander")]
fn device_id(h: Handle) -> Option<azos_drv_base::instances::DeviceId> {
    hwbus::with(|b| b.get(h).map(|s| azos_drv_base::instances::DeviceId { handle: h.0, generation: s.generation() }))
}

/// The patience of an unbind waiting for the ops inside a controller: Kconfig
/// `INSTANCE_UNBIND_WAIT_US` from the first time it is asked.
#[cfg(feature = "gpio-soft-expander")]
fn unbind_wait() -> impl FnMut() -> bool {
    use azos_drv_sys::timebase::{now, TIMER_FREQ};
    let wait = azos_limits::INSTANCE_UNBIND_WAIT_US as u64 * TIMER_FREQ / 1_000_000;
    let mut end = None;
    move || {
        let t = now();
        t < *end.get_or_insert(t.saturating_add(wait.max(1)))
    }
}

/// Does a device other than `h` bound to a kernel driver share `line`? It
/// sees what a device's `irq` names: a virtio-mmio slot's line; a PCI function
/// carries `irq` 0, so an INTx co-user is not seen (no PCI driver has an
/// unbind yet: one that gets it stores its routed GSI there first). It takes
/// the bus lock from a driver op, which is safe only because the bus calls
/// `remove` with its lock released (`Access::unbind`).
fn line_shared(h: Handle, line: u32) -> bool {
    hwbus::with(|b| {
        b.iter().any(|(o, s)| {
            o != h && s.dev.irq == line && s.state == hwbus::State::Bound && matches!(s.binding, hwbus::Binding::Native(_))
        })
    })
}

fn booked(h: Handle) -> Held {
    HELD.lock().get(h.index()).copied().unwrap_or(Held::NONE)
}

/// The virtio-mmio device whose transport is at `base`, in any state (a
/// rebind wires its line while the bus has it `Probing`).
pub(crate) fn handle_at(base: usize) -> Option<Handle> {
    hwbus::with(|b| {
        b.iter()
            .find(|(_, s)| s.dev.kind == hwbus::BusKind::VirtioMmio && s.dev.base == base as u64)
            .map(|(h, _)| h)
    })
}

/// The device's window is the driver's and it may DMA: what a probe that
/// brought it up books, and an unbind that stopped it gives back.
fn book_live(h: Handle, live: bool) {
    hold(h, |held| {
        held.window = live;
        held.dma = live;
    });
}

impl Env for KernelEnv<'_> {
    /// The clocks, resets, power domains and `default` pin state the device's
    /// node names (`boot::soc::bind`), before its driver is asked. Pinned
    /// hardware is out: the kernel brought it up before the SoC frameworks
    /// existed, outside the bus. A device that did not come from the tree has
    /// no node, and a node without the properties asks for nothing.
    fn resources(&mut self, driver: &str, _h: Handle, dev: &Device) -> Result<(), ProbeError> {
        #[cfg(feature = "soc")]
        if let (true, Some(node)) = (super::hwbus::wants_resources(driver), dev.dt_node) {
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
        if let (true, Some(node)) = (super::hwbus::wants_resources(driver), dev.dt_node) {
            if let Err(e) = super::soc::unbind(node) {
                azos_drv_sys::kwarn!("[HWBUS] {} resources of {} not all released: {:?}", dev.name.as_str(), driver, e);
            }
        }
        let _ = (driver, dev);
    }

    /// The books, and the line binding: a line the IRQ thread still has bound
    /// is held whatever the books say.
    fn held(&mut self, h: Handle, dev: &Device) -> Held {
        let mut held = booked(h);
        if held.irq.is_none() && dev.irq != 0 && azos_ipc::irq_bind::irq_bindings_of(dev.irq) != 0 {
            held.irq = Some(dev.irq);
        }
        held
    }
}

type R = Result<(), ProbeError>;

/// The kernel's record table, one record per generated id entry.
macro_rules! records {
    ($($i:literal $id:ident)*) => {
        pub(crate) static RECORDS: [Record<Kernel>; hwbus::DRIVERS.len()] =
            [$(Record { ids: &hwbus::DRIVERS[$i], ops: &$id }),*];
    };
}
hwbus::native_drivers!(records);

/// Is `driver`'s record pinned (hardware the kernel drives outside the bus)?
pub(crate) fn pinned(driver: &str) -> bool {
    hwbus::record::find(&RECORDS, driver).is_some_and(|r| matches!(r.ops.unbind, Unbind::Pinned))
}

const fn unbind(f: Op<Kernel>) -> Unbind<Kernel> {
    Unbind::<Kernel>::Op(f)
}

const fn power(suspend: Op<Kernel>, resume: Op<Kernel>) -> Power<Kernel> {
    Power::<Kernel>::Op { suspend, resume }
}

/// `Busy` when the driver already holds a device (a second one is not its
/// business), `Failed` when it tried and the hardware refused.
fn refusal(already_up: bool) -> ProbeError {
    if already_up { ProbeError::Busy } else { ProbeError::Failed }
}

/// A driver whose probe brings a device up and has no unbind, power ops or
/// reset yet.
const fn bring_up(probe: Op<Kernel>) -> Ops<Kernel> {
    Ops { probe, unbind: Unbind::Unsupported, power: Power::Unsupported }
}

// ── Pinned: hardware the kernel brought up before the bus ───────────────

fn record_only(_: &mut KernelEnv<'_>, _: Handle, _: &Device) -> R {
    Ok(())
}

/// The binding only records that the device is the kernel's, so ring 3 is
/// never handed a window the kernel is using. Its state across a suspend is
/// the platform's save and restore (the interrupt controller, the console).
const PINNED: Ops<Kernel> = Ops { probe: record_only, unbind: Unbind::Pinned, power: Power::Stateless };

const UART: Ops<Kernel> = PINNED;
const INTC: Ops<Kernel> = PINNED;
const PCI_HOST: Ops<Kernel> = PINNED;
const CCACHE: Ops<Kernel> = PINNED;
#[cfg(feature = "ramfb")]
const RAMFB: Ops<Kernel> = PINNED;
#[cfg(feature = "fb-generic")]
const FB_SIMPLE: Ops<Kernel> = PINNED;
#[cfg(any(feature = "soc-jh7110", feature = "soc-k1"))]
const SOC: Ops<Kernel> = PINNED;
#[cfg(feature = "iommu-riscv")]
const RISCV_IOMMU: Ops<Kernel> = PINNED;
#[cfg(feature = "iommu-smmuv3")]
const SMMUV3: Ops<Kernel> = PINNED;

// ── virtio-mmio ─────────────────────────────────────────────────────────

/// A rebind after the boot wired the line wires it again.
fn virtio_blk_probe(_: &mut KernelEnv<'_>, h: Handle, dev: &Device) -> R {
    use azos_drv_virtio::virtio::blk;
    blk::init_at(dev.base as usize).map_err(|_| refusal(blk::init().is_ok()))?;
    azos_drv_block::queue::rebound(&blk::VIRTIO_BLK);
    book_live(h, true);
    if super::virtio_blk_irq_stage_ran() {
        super::wire_virtio_blk_irq();
    }
    Ok(())
}
/// Is the virtio disk the block layer's medium with a volume mounted on it or
/// swap on it? The block layer keeps no count of openers; these are the ones
/// the kernel has (a ring-3 client of the block interface is not counted).
fn disk_in_use() -> bool {
    let medium = azos_drv_block::queue::bound().is_some_and(|q| {
        core::ptr::addr_eq(q as *const dyn azos_drv_api::block::HwQueue, &azos_drv_virtio::virtio::blk::VIRTIO_BLK as *const _)
    });
    medium && (azos_fs::vfs_block_mounts() != 0 || azos_mm::pager::swap_on())
}

/// `Busy` while the disk is in use ([`disk_in_use`]), and while another kernel
/// driver's device shares its line (masking it would take theirs). Otherwise the device
/// out of service (what it was given finished, its reset confirmed), its line
/// given back, and its memory taken out of its DMA domain (`blk::release`): a
/// later `claim` finds it gone. A release the domain refuses leaves the DMA
/// booked, so the bus reads the unbind as leaked and binds the driver again.
fn virtio_blk_unbind(_: &mut KernelEnv<'_>, h: Handle, dev: &Device) -> R {
    use azos_drv_virtio::virtio::blk;
    if disk_in_use() {
        if !canary!("unbind-ignores-openers") {
            return Err(ProbeError::Busy);
        }
        crate::kprintln!("[CANARY] unbind-ignores-openers: virtio-blk lets go of a disk in use");
    }
    if booked(h).irq.is_some_and(|line| line_shared(h, line)) {
        return Err(ProbeError::Busy);
    }
    blk::park(dev.base as usize).map_err(|()| ProbeError::Busy)?;
    if canary!("unbind-leaves-irq") {
        crate::kprintln!("[CANARY] unbind-leaves-irq: virtio-blk's unbind keeps its interrupt line");
        book_live(h, false);
        return Ok(());
    }
    if let Some(line) = booked(h).irq {
        let target = LINE_TARGET.lock().get(h.index()).copied().unwrap_or(0);
        super::unwire_line(line, target);
        hold(h, |held| held.irq = None);
    }
    blk::irq_mode_off();
    if blk::release(dev.base as usize).is_err() {
        hold(h, |held| held.window = false);
        return Ok(());
    }
    book_live(h, false);
    Ok(())
}
/// The line stays wired across a suspend: a reset device raises nothing.
fn virtio_blk_suspend(_: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    if canary!("suspend-leaves-disk-up") {
        crate::kprintln!("[CANARY] suspend-leaves-disk-up: virtio-blk's suspend does nothing");
        return Ok(());
    }
    azos_drv_virtio::virtio::blk::park(dev.base as usize).map_err(|()| ProbeError::Busy)
}
fn virtio_blk_resume(_: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    azos_drv_virtio::virtio::blk::init_at(dev.base as usize).map_err(|()| ProbeError::Failed)
}
const VIRTIO_BLK: Ops<Kernel> = Ops {
    unbind: unbind(virtio_blk_unbind),
    power: power(virtio_blk_suspend, virtio_blk_resume),
    ..bring_up(virtio_blk_probe)
};

fn virtio_net_probe(_: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    use azos_drv_virtio::virtio::net;
    net::init_at(dev.base as usize).map_err(|_| refusal(net::is_ready()))
}
/// The NIC is one device on either transport: its suspend and resume are the
/// driver's.
fn virtio_net_suspend(_: &mut KernelEnv<'_>, _: Handle, _: &Device) -> R {
    azos_drv_virtio::virtio::net::suspend().map_err(|()| ProbeError::Busy)
}
fn virtio_net_resume(_: &mut KernelEnv<'_>, _: Handle, _: &Device) -> R {
    azos_drv_virtio::virtio::net::resume().map_err(|()| ProbeError::Failed)
}
const VIRTIO_NET: Ops<Kernel> = Ops { power: power(virtio_net_suspend, virtio_net_resume), ..bring_up(virtio_net_probe) };

// With Kconfig DRV_VIRTIO_RNG_PLACEMENT = ring3 the id table has no
// `virtio-rng` entry (crates/drivers/virtio/hwbus.ids): the ring-3 driver
// takes the device, and these ops have no record.

/// Polled: the device has no line. Nothing sets it up until the first seed
/// read.
#[cfg_attr(feature = "virtio-rng-ring3", allow(dead_code))]
fn virtio_rng_probe(_: &mut KernelEnv<'_>, h: Handle, dev: &Device) -> R {
    azos_drv_virtio::virtio::rng::bind(dev.base as usize).map_err(|_| ProbeError::Busy)?;
    book_live(h, true);
    Ok(())
}
#[cfg_attr(feature = "virtio-rng-ring3", allow(dead_code))]
fn virtio_rng_unbind(_: &mut KernelEnv<'_>, h: Handle, dev: &Device) -> R {
    azos_drv_virtio::virtio::rng::unbind(dev.base as usize).map_err(|_| ProbeError::Busy)?;
    book_live(h, false);
    Ok(())
}
#[cfg_attr(feature = "virtio-rng-ring3", allow(dead_code))]
fn virtio_rng_suspend(_: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    azos_drv_virtio::virtio::rng::suspend(dev.base as usize).map_err(|_| ProbeError::Busy)
}
/// The first read after the resume programs the device again.
#[cfg_attr(feature = "virtio-rng-ring3", allow(dead_code))]
fn virtio_rng_resume(_: &mut KernelEnv<'_>, _: Handle, _: &Device) -> R {
    Ok(())
}
#[cfg_attr(feature = "virtio-rng-ring3", allow(dead_code))]
const VIRTIO_RNG: Ops<Kernel> = Ops {
    unbind: unbind(virtio_rng_unbind),
    power: power(virtio_rng_suspend, virtio_rng_resume),
    ..bring_up(virtio_rng_probe)
};

#[cfg(feature = "virtio-input")]
fn virtio_input_probe(_: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    use azos_drv_virtio::virtio::input;
    input::init_at(dev.base as usize).map_err(|_| refusal(input::device_count() >= 1))
}
#[cfg(feature = "virtio-input")]
const VIRTIO_INPUT: Ops<Kernel> = bring_up(virtio_input_probe);

#[cfg(feature = "fb-generic")]
fn virtio_gpu_probe(_: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    azos_drv_virtio::virtio::gpu::init_at(dev.base as usize).map_err(|_| ProbeError::Failed)
}
#[cfg(feature = "fb-generic")]
const VIRTIO_GPU: Ops<Kernel> = bring_up(virtio_gpu_probe);

#[cfg(feature = "virtio-snd")]
fn virtio_snd_probe(_: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    azos_drv_virtio::virtio::snd::init_at(dev.base as usize).map_err(|_| ProbeError::Failed)
}
#[cfg(feature = "virtio-snd")]
const VIRTIO_SND: Ops<Kernel> = bring_up(virtio_snd_probe);

// ── PCI (the configuration space is the bring-up's, `boot::pci`) ────────

#[cfg(feature = "pci")]
fn virtio_net_pci_probe(env: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    super::pci::probe_virtio_net_pci(env.pci_fn(dev)?, dev)
}
#[cfg(feature = "pci")]
const VIRTIO_NET_PCI: Ops<Kernel> = Ops { power: power(virtio_net_suspend, virtio_net_resume), ..bring_up(virtio_net_pci_probe) };

#[cfg(all(feature = "fb-generic", feature = "pci"))]
fn virtio_gpu_pci_probe(env: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    super::pci::probe_virtio_gpu_pci(env.pci_fn(dev)?, dev)
}
#[cfg(all(feature = "fb-generic", feature = "pci"))]
const VIRTIO_GPU_PCI: Ops<Kernel> = bring_up(virtio_gpu_pci_probe);

#[cfg(all(feature = "virtio-snd", feature = "pci"))]
fn virtio_snd_pci_probe(env: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    super::pci::probe_virtio_snd_pci(env.pci_fn(dev)?, dev)
}
#[cfg(all(feature = "virtio-snd", feature = "pci"))]
const VIRTIO_SND_PCI: Ops<Kernel> = bring_up(virtio_snd_pci_probe);

#[cfg(feature = "nvme")]
fn nvme_probe(env: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    super::pci::probe_nvme(env.pci_fn(dev)?, dev)
}
#[cfg(feature = "nvme")]
const NVME: Ops<Kernel> = bring_up(nvme_probe);

#[cfg(feature = "ahci")]
fn ahci_probe(env: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    super::pci::probe_ahci(env.pci_fn(dev)?, dev)
}
#[cfg(feature = "ahci")]
const AHCI: Ops<Kernel> = bring_up(ahci_probe);

#[cfg(feature = "e1000e")]
fn e1000e_probe(env: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    super::pci::probe_e1000e(env.pci_fn(dev)?, dev)
}
#[cfg(feature = "e1000e")]
const E1000E: Ops<Kernel> = bring_up(e1000e_probe);

#[cfg(feature = "igc")]
fn igc_probe(env: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    super::pci::probe_igc(env.pci_fn(dev)?, dev)
}
#[cfg(feature = "igc")]
const IGC: Ops<Kernel> = bring_up(igc_probe);

#[cfg(feature = "pci-soc-host")]
fn rp1_probe(env: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    super::pci::probe_rp1(env.pci_fn(dev)?, dev)
}
#[cfg(feature = "pci-soc-host")]
const RP1: Ops<Kernel> = bring_up(rp1_probe);

#[cfg(all(feature = "i2c-dw", feature = "pci"))]
fn i2c_lpss_spt_probe(env: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    super::pci::probe_lpss_i2c(env.pci_fn(dev)?, "i2c-lpss-spt", dev)
}
#[cfg(all(feature = "i2c-dw", feature = "pci"))]
const I2C_LPSS_SPT: Ops<Kernel> = bring_up(i2c_lpss_spt_probe);

#[cfg(all(feature = "i2c-dw", feature = "pci"))]
fn i2c_lpss_cnl_probe(env: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    super::pci::probe_lpss_i2c(env.pci_fn(dev)?, "i2c-lpss-cnl", dev)
}
#[cfg(all(feature = "i2c-dw", feature = "pci"))]
const I2C_LPSS_CNL: Ops<Kernel> = bring_up(i2c_lpss_cnl_probe);

// ── Board controllers: the node's window, mapped, to the driver ─────────

// A second node for a one-controller driver is `Busy`. The GPIO window is
// mapped here even though the SoC pinctrl framework maps the same one
// (`boot::soc::install`, when it comes up): the e-stop line does not depend
// on another framework's success. The mapping record covers an identical
// window already, so the second call costs no MAX_MMIO_REGIONS slot.
#[cfg(any(feature = "vf2", feature = "k1"))]
fn gpio_probe(_: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    super::hwbus::attach_gpio(dev)
}
#[cfg(any(feature = "vf2", feature = "k1"))]
const GPIO: Ops<Kernel> = bring_up(gpio_probe);

// The development kernel's soft expander: its probe registers it as the next
// GPIO controller, its unbind withdraws it once no op is inside it, and the
// number stays the device's.
#[cfg(feature = "gpio-soft-expander")]
fn gpio_soft_probe(_: &mut KernelEnv<'_>, h: Handle, _: &Device) -> R {
    let dev = device_id(h).ok_or(ProbeError::Failed)?;
    let ctrl = azos_drv_gpio::chips::register(dev, &azos_drv_gpio::expander::EXPANDER).map_err(|_| ProbeError::Busy)?;
    crate::kprintln!("[GPIO] soft expander: controller {}, {} pins ({} controllers registered)",
        ctrl, azos_drv_gpio::expander::PINS, azos_drv_gpio::chips::count());
    Ok(())
}
#[cfg(feature = "gpio-soft-expander")]
fn gpio_soft_unbind(_: &mut KernelEnv<'_>, h: Handle, _: &Device) -> R {
    let dev = device_id(h).ok_or(ProbeError::Failed)?;
    azos_drv_gpio::chips::unregister(dev, &mut unbind_wait()).map(|_| ()).map_err(|e| {
        azos_drv_sys::kwarn!("[GPIO] the soft expander stays bound: {:?}", e);
        ProbeError::Failed
    })
}
#[cfg(feature = "gpio-soft-expander")]
const GPIO_SOFT: Ops<Kernel> = Ops { probe: gpio_soft_probe, unbind: unbind(gpio_soft_unbind), power: Power::Stateless };

#[cfg(all(any(feature = "vf2", feature = "k1"), feature = "board-io"))]
fn pwm_probe(_: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    azos_drv_actuator::pwm::pwm_attach(super::hwbus::map_window(dev)?).map_err(|_| ProbeError::Busy)
}
#[cfg(all(any(feature = "vf2", feature = "k1"), feature = "board-io"))]
const PWM: Ops<Kernel> = bring_up(pwm_probe);

/// A device-tree node here; the AMD FCH's SMBus function through the PCI
/// bring-up (it reads the revision).
#[cfg(any(feature = "vf2", feature = "wdt-sbsa", feature = "wdt-sp5100"))]
fn wdt_probe(env: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    match dev.kind {
        #[cfg(feature = "wdt-sp5100")]
        hwbus::BusKind::Pci => super::pci::probe_sp5100(env.pci_fn(dev)?, dev),
        _ => {
            let _ = env;
            super::hwbus::attach_wdt(dev)
        }
    }
}
#[cfg(any(feature = "vf2", feature = "wdt-sbsa", feature = "wdt-sp5100"))]
const WDT: Ops<Kernel> = bring_up(wdt_probe);

// arch-only: the BCM2835 PM block is the Raspberry Pis', and the Pis are aarch64.
#[cfg(all(feature = "wdt-bcm2835-pm", target_arch = "aarch64"))]
fn pm_wdt_probe(_: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    if dev.size < azos_drv_power::bcm2835_pm::MIN_WINDOW {
        return Err(ProbeError::Failed);
    }
    crate::entry::aarch64::ext::rpi_pm::attach(super::hwbus::map_window(dev)?).map_err(|_| ProbeError::Busy)
}
#[cfg(all(feature = "wdt-bcm2835-pm", target_arch = "aarch64"))]
const PM_WDT: Ops<Kernel> = bring_up(pm_wdt_probe);

#[cfg(feature = "vf2")]
fn dw_mshc_probe(_: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    super::hwbus::attach_dwmshc(dev)
}
#[cfg(feature = "vf2")]
const DW_MSHC: Ops<Kernel> = bring_up(dw_mshc_probe);

/// One probe per controller the tree enables; the bus number is the order
/// they bind in (`i2c_attach`). A DesignWare node brings its timing facts.
#[cfg(any(feature = "i2c-dw", feature = "k1"))]
fn i2c_probe(_: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    super::hwbus::attach_i2c_node(dev, super::hwbus::map_window(dev)?)
}
#[cfg(any(feature = "i2c-dw", feature = "k1"))]
const I2C: Ops<Kernel> = bring_up(i2c_probe);

// The thermal sensors: the kernel's thermal task reads them (`boot::thermal`,
// which keeps the window). The VisionFive 2's `sfctemp` is powered up and
// left converting; the K1's five-channel block checks the window it is given
// (its clock and reset are the platform's: the APBC controller has no
// provider); the Raspberry Pi's VideoCore mailbox is both sensor and ARM
// clock.
#[cfg(all(feature = "vf2", feature = "thermal"))]
fn sfctemp_probe(_: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    super::thermal::attach_sfctemp(super::hwbus::map_window(dev)?);
    Ok(())
}
#[cfg(all(feature = "vf2", feature = "thermal"))]
const SFCTEMP: Ops<Kernel> = bring_up(sfctemp_probe);

#[cfg(all(feature = "soc-k1", feature = "thermal"))]
fn k1_tsensor_probe(_: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    super::thermal::attach_k1_tsensor(super::hwbus::map_window(dev)?).map_err(|_| ProbeError::Failed)
}
#[cfg(all(feature = "soc-k1", feature = "thermal"))]
const K1_TSENSOR: Ops<Kernel> = bring_up(k1_tsensor_probe);

// arch-only: the Raspberry Pi boards are aarch64; no other ISA has this firmware.
#[cfg(all(feature = "rpi-firmware", target_arch = "aarch64"))]
fn rpi_mbox_probe(_: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    crate::entry::aarch64::ext::rpi_mbox::attach(super::hwbus::map_window(dev)?);
    Ok(())
}
#[cfg(all(feature = "rpi-firmware", target_arch = "aarch64"))]
const RPI_MBOX: Ops<Kernel> = bring_up(rpi_mbox_probe);

// ── USB host controllers ────────────────────────────────────────────────

/// A device-tree node is mapped and started here; a PCI function needs the
/// bring-up's configuration space.
#[cfg(feature = "usb-xhci")]
fn xhci_probe(env: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    match dev.kind {
        hwbus::BusKind::Dt => super::usb::attach_dt(dev),
        #[cfg(feature = "pci")]
        hwbus::BusKind::Pci => super::pci::probe_xhci(env.pci_fn(dev)?, dev),
        _ => {
            let _ = env;
            Err(ProbeError::NoSuchDriver)
        }
    }
}
#[cfg(feature = "usb-xhci")]
const XHCI: Ops<Kernel> = bring_up(xhci_probe);

/// A DesignWare USB 2.0 core (the Raspberry Pi's): device tree only.
#[cfg(feature = "usb-dwc2")]
fn dwc2_probe(_: &mut KernelEnv<'_>, _: Handle, dev: &Device) -> R {
    super::usb::attach_dwc2(dev)
}
#[cfg(feature = "usb-dwc2")]
const DWC2: Ops<Kernel> = bring_up(dwc2_probe);

// ── In-kernel rows ──────────────────────────────────────────────────────

// Each device bound to a driver whose record has an unbind is unbound and
// bound again once, through the bus, except the disk while a volume or swap
// is on it, whose unbind must be refused (it is never parked under its
// users); the disk and the entropy device are read after. Canary
// `unbind-ignores-openers`: the disk in use lets go and this test fails. The QEMU row attaches a disk and pins the count line, so a run
// that bound nothing with an unbind is not a pass. Canary
// `unbind-leaves-irq`: the disk's unbind keeps its line, the bus keeps the
// device bound and this test fails.
#[cfg(feature = "ktest")]
azos_ktest::ktest_late! {
    fn driver_records_unbind_and_rebind_each_bound_driver() {
        use azos_drv_bus::hwbus::{Binding, State};
        let (mut n, mut refused, mut cycled_disk) = (0, false, false);
        for i in 0..hwbus::MAX_DEVICES as u32 {
            let h = Handle(i);
            let bound = hwbus::with(|b| match b.get(h) {
                Some(s) if s.state == State::Bound => match s.binding {
                    Binding::Native(name) => Some(name),
                    _ => None,
                },
                _ => None,
            });
            let Some(name) = bound else { continue };
            let Some(rec) = hwbus::record::find(&RECORDS, name.as_str()) else {
                return Err("a bound driver has no record");
            };
            if !matches!(rec.ops.unbind, Unbind::Op(_)) {
                continue;
            }
            let disk = rec.name() == "virtio-blk";
            if disk && disk_in_use() {
                if super::hwbus::unbind_rebind(h, rec.name()) != Err(hwbus::UnbindError::Refused) {
                    return Err("an unbind of the disk in use was not refused");
                }
                refused = true;
            } else {
                if super::hwbus::unbind_rebind(h, rec.name()).is_err() {
                    return Err("a device did not unbind and bind again through its record");
                }
                cycled_disk |= disk;
                n += 1;
            }
            if !hwbus::with(|b| b.get(h).is_some_and(|s| s.state == State::Bound)) {
                return Err("a device is not bound after its unbind and rebind, or its refusal");
            }
        }
        let mut sector = [0u8; 512];
        if azos_drv_virtio::virtio::blk::init().is_ok() && azos_drv_block::blkdev::read_quiet(0, 1, &mut sector).is_err() {
            return Err("the disk does not read after its rebind");
        }
        let mut seed = [0u8; 16];
        if matches!(azos_drv_virtio::virtio::rng::read_seed(&mut seed), azos_drv_virtio::virtio::rng::SeedRead::Failed(_)) {
            return Err("the entropy device does not read after its rebind");
        }
        if refused {
            crate::kprintln!("[KTEST] driver records: the disk in use refused its unbind");
        }
        crate::kprintln!("[KTEST] driver records: {} device(s) unbound and bound again{}", n,
            if cycled_disk { ", the disk among them" } else { "" });
        Ok(())
    }
}

// A system suspend's device step on the real bus (volumes synced, write-back
// held): every device a kernel driver is bound to goes down through its
// record (the disk and the NIC are seen down) and comes back, or the first
// that cannot refuses and none is left down; the disk reads after. Not run
// while a volume or swap is on the disk: the late phase of the other rows
// never parks their mounted disk (the scratch-disk rows run it). Canary `suspend-leaves-disk-up`: the
// disk's suspend does nothing and this test fails.
#[cfg(feature = "ktest")]
azos_ktest::ktest_late! {
    fn driver_records_quiesce_and_bring_back_every_kernel_device() {
        if disk_in_use() {
            crate::kprintln!("[KTEST] driver records: quiesce not run: a volume or swap is on the disk");
            return Ok(());
        }
        let (disk_up, nic_up) = (azos_drv_virtio::virtio::blk::init().is_ok(), azos_drv_virtio::virtio::net::is_ready());
        let downed = super::hwbus::quiesce();
        let left = hwbus::with(|b| b.iter().filter(|(h, _)| b.suspended(*h)).count());
        match downed {
            Ok(()) => {
                let still_up = (disk_up && azos_drv_virtio::virtio::blk::init().is_ok())
                    || (nic_up && azos_drv_virtio::virtio::net::is_ready());
                let failed = super::hwbus::unquiesce();
                if still_up {
                    return Err("a quiesced device was still up");
                }
                if failed != 0 {
                    return Err("a device did not come back after the quiesce");
                }
                let among = match (disk_up, nic_up) {
                    (true, true) => ", the disk and the NIC among them",
                    (true, false) => ", the disk among them",
                    (false, true) => ", the NIC among them",
                    (false, false) => "",
                };
                crate::kprintln!("[KTEST] driver records: {} device(s) quiesced and brought back{}", left, among);
            }
            Err(_) if left != 0 => return Err("a refused quiesce left devices down"),
            Err(_) => crate::kprintln!("[KTEST] driver records: quiesce refused by a driver without power ops"),
        }
        if hwbus::with(|b| b.iter().any(|(h, _)| b.suspended(h))) {
            return Err("a device is still down after the resume");
        }
        let mut sector = [0u8; 512];
        if azos_drv_virtio::virtio::blk::init().is_ok() && azos_drv_block::blkdev::read_quiet(0, 1, &mut sector).is_err() {
            return Err("the disk does not read after the resume");
        }
        Ok(())
    }
}

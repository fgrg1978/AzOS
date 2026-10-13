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
//! controllers and timers, the PCI host bridge, the firmware framebuffer) are
//! hardware the kernel drives outside the bus. They bind to a driver that only
//! records the fact, so ring 3 can never be handed a window the kernel is
//! using.

use azos_drv_bus::hwbus::{
    self, Binding, Choice, Device, Drivers, Event, Handle, Pattern, Policy, ProbeError, Row, Rules, Sink,
    State, Verdict, LINUX, NATIVE,
};
use core::fmt::Write as _;

use crate::kprintln;

/// Drivers the kernel brought up before the bus, or without asking it: the
/// binding only records that the device is the kernel's.
const RECORD_ONLY: [&str; 5] = ["uart", "intc", "pci-host", "ramfb", "fb-simple"];

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
            #[cfg(feature = "virtio-input")]
            "virtio-input" => azos_drv_virtio::virtio::input::init_at(base)
                .map_err(|_| refusal(azos_drv_virtio::virtio::input::device_count() >= 1)),
            #[cfg(feature = "pci")]
            "nvme" | "virtio-net-pci" => match self.pci.as_mut() {
                Some(p) => p.probe(driver, dev),
                None => Err(ProbeError::Failed),
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
    let _ = hwbus::with(|b| b.add(dev, &mut Console));
}

/// Enumerate what the firmware describes: the device tree's nodes (riscv64,
/// aarch64) and the populated virtio-mmio windows, then bind the kernel's own
/// hardware among them. Call after the late MMIO windows are mapped.
pub(crate) fn enumerate_firmware(dtb_ptr: usize) {
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
                    return;
                }
                let name = core::str::from_utf8(d.name).unwrap_or("?");
                add(Device::dt(name, d.compatible, d.base, d.size, d.irq));
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
            add(Device::virtio_mmio(base as u64, VIRTIO_MMIO_STRIDE as u64, irq, v.device_id));
        }
    }

    // The kernel's own hardware among them is bound now: it was brought up
    // before this point.
    bind(&RECORD_ONLY);
}

/// Add the PCI/PCIe functions the bring-up enumerated. The first assigned
/// memory BAR of a function is the register window ring 3 may be granted
/// when no kernel driver binds it.
#[cfg(feature = "pci")]
pub(crate) fn add_pci(funcs: &[Option<azos_pci::FunctionInfo>]) {
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
            d = d.with_window(bar.address, bar.size);
        }
        add(d);
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
        hwbus::with(|b| {
            b.bind_where(rules, &mut kd, &mut Console, &|_, v| {
                matches!(v, Verdict::Bind(Choice::Native(n)) if drivers.contains(n))
            })
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
        hwbus::with(|b| {
            b.bind_where(rules, &mut kd, &mut Console, &|_, v| {
                !matches!(v, Verdict::Bind(Choice::Native(n)) if later.contains(n))
            })
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
    with_rules(|rules| hwbus::with(|b| b.reconcile(rules, &mut kd, &mut Console)));
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

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A DTB-instantiated (or platform-table-instantiated) device bus.
//!
//! # Shape, and where it comes from
//!
//! Modelled on the Linux driver model's separation
//! (<https://www.kernel.org/doc/html/v6.6/driver-api/driver-model/overview.html>),
//! taken for its SHAPE only, not its code: a bus enumerates [`Device`]s from
//! resources (register base/size, IRQ, `compatible`, where those resources
//! came from); a [`Driver`] declares which `compatible` strings it answers
//! to and a `probe(&Device)` that reads its resources FROM the device, never
//! from a `platform::hw` constant baked into the driver body. Binding is the
//! bus walking devices, matching each against every driver's table, and
//! calling `probe` on the first match; an unmatched device is reported, not
//! silently ignored. `no_std`, no sysfs, no hotplug — this is a boot-time
//! enumeration + one-shot bind, not a running device model.
//!
//! This is the mechanism fix U05-1 asked for: today every MMIO address is a
//! compile-time constant and the real device's `compatible` string lives in
//! a comment (see `platform.rs`'s corrected constants) — this crate has no
//! way to notice at boot that a constant and the hardware it names have
//! drifted apart. With this bus, binding a device to the wrong driver, or
//! having no driver at all, is a printed line at boot, not a silent
//! mis-program.
//!
//! # What is real here vs. what is a diff
//!
//! [`Device`], [`Driver`], [`matches`] and [`bind_and_probe`] are pure and
//! run on QEMU `virt` today wherever this crate's own driver `init` calls
//! already run (they are safe to call more than once — see each `probe`
//! below). Feeding this bus the LIVE DTB values for `uart0`/`plic` (as
//! opposed to `platform::hw`'s compile-time constants) needs the parsed
//! `azos_dtb::DtbInfo` that only `kernel/src/entry/riscv64/
//! boot_hooks.rs` holds — not this crate's file to edit this wave; see the
//! diff in this front's report for the one call this bus needs there.
//!
//! # Suspend/resume seam (U05-10)
//!
//! `Driver::suspend`/`Driver::resume` are declared with no-op defaults and
//! called by nothing yet. U05-10 found this crate's `Driver` trait
//! (`azos_drv_api`) has `shutdown` only, no per-device suspend/resume hook a
//! low-power profile needs — rather than add that to the OTHER trait (not
//! this front's file), the seam lives here so a future wake-source registry
//! has a call site to reach into once it exists.
//!
//! # Sizing
//!
//! Fixed-capacity, sized by [`azos_drv_api::REGISTRY_MAX_DRIVERS`]
//! (32) rather than a new `azos_limits`/Kconfig symbol: that constant
//! already describes "how many drivers this kernel can hold" for the
//! existing `REGISTRY`, this bus's device table is the same shape of
//! bound, and adding a new Kconfig symbol this wave touches `Kconfig.*`
//! files another front owns mid-edit (see `git status`).
//!
//! # Dispatch cost
//!
//! `&'static dyn Driver` in a fixed array, not an enum: `bind_and_probe`
//! calls `probe` at most once per device at boot, never on a hot path, so
//! the vtable indirection this pulls in costs nothing worth measuring here
//! — contrast `pwm_driver.rs`'s per-syscall `dyn Driver` dispatch, which
//! IS hot and where `crates/core/syscall`'s own `.text` measurement matters.

use azos_drv_api::REGISTRY_MAX_DRIVERS as MAX_DEVICES;

/// Where a [`Device`]'s resources came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    /// Read from a live, parsed DTB this boot.
    Dtb,
    /// No DTB field for this device on this boot (or no DTB at all) — the
    /// compile-time `platform::hw` table stood in.
    PlatformTable,
}

impl Source {
    pub const fn as_str(self) -> &'static str {
        match self {
            Source::Dtb => "dtb",
            Source::PlatformTable => "platform-table",
        }
    }
}

/// One device's resources — exactly what a [`Driver::probe`] may read.
#[derive(Clone, Copy)]
pub struct Device {
    pub name: &'static str,
    pub compatible: &'static str,
    pub base: usize,
    pub size: usize,
    pub irq: u32,
    pub source: Source,
}

/// A driver: which `compatible` strings it answers to, and its lifecycle.
/// `probe`/`remove` mirror the Linux shape's bind/unbind; `suspend`/
/// `resume` are the seam this module's doc describes.
pub trait Driver {
    /// Every `compatible` string this driver answers to, most-specific
    /// first (mirrors a DT `compatible` property's own fallback order).
    fn compatible(&self) -> &'static [&'static str];
    /// Bind to `dev`. Must read `dev.base`/`dev.irq`, never a
    /// `platform::hw` constant of its own — that is the whole point of
    /// taking `&Device` instead of nothing.
    fn probe(&self, dev: &Device) -> Result<(), ()>;
    fn remove(&self) {}
    /// U05-10 seam — not called by anything yet.
    fn suspend(&self) {}
    /// U05-10 seam — not called by anything yet.
    fn resume(&self) {}
}

/// Does `driver` answer to `dev.compatible`? Pure, host-tested.
pub fn matches(driver: &dyn Driver, dev: &Device) -> bool {
    driver.compatible().iter().any(|c| *c == dev.compatible)
}

/// Bind every device in `devices` to the first driver in `drivers` whose
/// `compatible` table matches, `probe` it, and print one boot line per
/// device — bound (with the driver's own probe result) or `UNBOUND`.
///
/// `devices`/`drivers` are `&[...]` rather than fixed arrays so a caller can
/// hand this a `heapless`-style stack array of any length up to
/// [`MAX_DEVICES`] — enforced by [`DeviceTable`] below, not here, so this
/// function itself stays independent of how the table was built.
pub fn bind_and_probe(devices: &[Device], drivers: &[&dyn Driver]) {
    for dev in devices {
        let mut bound = false;
        for drv in drivers {
            if matches(*drv, dev) {
                let ok = drv.probe(dev).is_ok();
                azos_drv_sys::kprintln!(
                    "[HWBUS] {} compatible={} base={:#x} irq={} source={} driver={}",
                    dev.name, dev.compatible, dev.base, dev.irq, dev.source.as_str(),
                    if ok { "bound" } else { "probe-failed" },
                );
                bound = true;
                break;
            }
        }
        if !bound {
            azos_drv_sys::kprintln!(
                "[HWBUS] {} compatible={} base={:#x} irq={} source={} UNBOUND (no matching driver)",
                dev.name, dev.compatible, dev.base, dev.irq, dev.source.as_str(),
            );
        }
    }
}

/// Fixed-capacity device table a board's boot path builds once. Board
/// tables are free functions below (`qemu_virt_riscv64_devices`, …), not
/// methods, so a board that needs none of this still costs nothing.
pub struct DeviceTable {
    devices: [Device; MAX_DEVICES],
    len: usize,
}

impl DeviceTable {
    pub const fn new() -> Self {
        const ZERO: Device = Device {
            name: "", compatible: "", base: 0, size: 0, irq: 0,
            source: Source::PlatformTable,
        };
        DeviceTable { devices: [ZERO; MAX_DEVICES], len: 0 }
    }

    /// Push a device. Silently drops it past [`MAX_DEVICES`] — a full
    /// table is a build-time-sized board description overflowing its own
    /// bound, which should be caught by giving the board fewer devices or
    /// raising the shared bound, not by panicking a boot path over a
    /// diagnostics table.
    pub fn push(&mut self, dev: Device) {
        if self.len < MAX_DEVICES {
            self.devices[self.len] = dev;
            self.len += 1;
        }
    }

    pub fn as_slice(&self) -> &[Device] {
        &self.devices[..self.len]
    }
}

// ── QEMU virt (riscv64): the verifiable case ────────────────────────────────
//
// `uart0`/`plic` take Source::Dtb when a caller supplies the live DTB base
// (boot_hooks.rs has it; this crate does not) — `dtb_uart_base`/
// `dtb_plic_base` of `0` means "no DTB this boot", matching
// `azos_dtb::DtbInfo`'s own zeroed-on-failure convention. `aia` is
// `virt,aia=aplic-imsic`: that machine has no PLIC, so the table lists none
// (it used to list one at the APLIC's address, or at `hw::PLIC_BASE`).
#[cfg(not(any(feature = "vf2", feature = "k1", all(target_arch = "aarch64", target_os = "none"), all(target_arch = "x86_64", target_os = "none"))))]
pub fn qemu_virt_riscv64_devices(dtb_uart_base: usize, dtb_plic_base: usize, aia: bool) -> DeviceTable {
    use azos_drv_base::platform::hw;
    let mut t = DeviceTable::new();
    let src = |dtb_base: usize| if dtb_base != 0 { Source::Dtb } else { Source::PlatformTable };
    t.push(Device {
        name: "uart0", compatible: hw::UART_COMPATIBLE,
        base: if dtb_uart_base != 0 { dtb_uart_base } else { hw::UART_BASE },
        size: 0x1000, irq: 10, source: src(dtb_uart_base),
    });
    if !aia {
        t.push(Device {
            name: "plic", compatible: hw::PLIC_COMPATIBLE,
            base: if dtb_plic_base != 0 { dtb_plic_base } else { hw::PLIC_BASE },
            size: 0x40_0000, irq: 0, source: src(dtb_plic_base),
        });
    }
    // `crates/drivers/dtb` extracts no virtio field (DTB has no fixed compatible
    // string per slot — each slot's device is probed at runtime, which
    // `virtio::mod`'s own transport already does). Listed here with
    // Source::PlatformTable so the window's presence is auditable in the
    // same boot log, not because a driver binds to it through this bus.
    t.push(Device {
        name: "virtio-mmio-window", compatible: "virtio,mmio",
        base: 0x1000_1000, size: 0x8000, irq: 1, source: Source::PlatformTable,
    });
    t
}

/// `uart0` driver: matches this board's confirmed compatible, `probe`
/// re-validates the resource shape rather than re-touching the UART MMIO
/// (that already happened in `boot_hooks.rs`'s Phase 1, before a DTB is
/// even parsed — see that file). Idempotent and safe to call every boot.
pub struct UartBusDriver;
impl Driver for UartBusDriver {
    fn compatible(&self) -> &'static [&'static str] {
        #[cfg(feature = "vf2")]
        { &["starfive,jh7110-uart"] }
        #[cfg(feature = "k1")]
        { &["spacemit,k1-uart"] }
        #[cfg(not(any(feature = "vf2", feature = "k1")))]
        { &["ns16550a"] }
    }
    fn probe(&self, dev: &Device) -> Result<(), ()> {
        if dev.base == 0 || dev.size == 0 { Err(()) } else { Ok(()) }
    }
}

/// `plic` driver: same idempotent-probe shape as [`UartBusDriver`].
pub struct PlicBusDriver;
impl Driver for PlicBusDriver {
    fn compatible(&self) -> &'static [&'static str] {
        #[cfg(feature = "vf2")]
        { &["starfive,jh7110-plic"] }
        #[cfg(feature = "k1")]
        { &["spacemit,k1-plic"] }
        #[cfg(not(any(feature = "vf2", feature = "k1")))]
        { &["sifive,plic-1.0.0"] }
    }
    fn probe(&self, dev: &Device) -> Result<(), ()> {
        if dev.base == 0 || dev.size == 0 { Err(()) } else { Ok(()) }
    }
}

/// The virtio transport window: this bus only records its presence
/// (`probe` always succeeds on a nonzero base) — binding a `virtio,mmio`
/// device does not initialise it; `virtio::mod`'s own per-slot probe does
/// that work independently and is unchanged by this module.
pub struct VirtioWindowBusDriver;
impl Driver for VirtioWindowBusDriver {
    fn compatible(&self) -> &'static [&'static str] { &["virtio,mmio"] }
    fn probe(&self, dev: &Device) -> Result<(), ()> {
        if dev.base == 0 { Err(()) } else { Ok(()) }
    }
}

/// Run the bus for QEMU virt (riscv64) with the given (possibly-zero) DTB
/// bases. Safe to call from `boot_hooks.rs` right after `dtb_parse`
/// succeeds — see this front's report for the exact call.
#[cfg(not(any(feature = "vf2", feature = "k1", all(target_arch = "aarch64", target_os = "none"), all(target_arch = "x86_64", target_os = "none"))))]
pub fn probe_qemu_virt_riscv64(dtb_uart_base: usize, dtb_plic_base: usize, aia: bool) {
    let table = qemu_virt_riscv64_devices(dtb_uart_base, dtb_plic_base, aia);
    let uart = UartBusDriver;
    let plic = PlicBusDriver;
    let virtio = VirtioWindowBusDriver;
    let drivers: [&dyn Driver; 3] = [&uart, &plic, &virtio];
    bind_and_probe(table.as_slice(), &drivers);
}

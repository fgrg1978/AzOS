// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The real-time clock at boot (Kconfig `DRV_RTC`): the kernel's one use of the
//! drivers in `azos_rtc`.
//!
//! The drivers are pure: they speak a chip's registers to a window, the ports
//! or a bus they are handed. This file is what only the kernel can do: find
//! the chip, map its window, hold the one device behind a lock, seed the wall
//! clock from it, and host the `Clock` interface's two RTC ops
//! ([`azos_syscall::clock::RtcHost`]).
//!
//! # Where the chip is
//!
//! * riscv64, aarch64: the first hardware-bus device compatible with
//!   `google,goldfish-rtc` (QEMU riscv64) or `arm,pl031` (QEMU aarch64). The
//!   bus only records where it is: the window is **not bound** to a driver,
//!   so it stays mappable by a task that holds its capability (the alarm and
//!   interrupt registers are not ours; this file reads the time and loads it,
//!   nothing else).
//! * x86_64: the CMOS clock on ports 0x70/0x71, unless the FADT says the
//!   machine has none (IAPC_BOOT_ARCH bit 5). Its century register is the one
//!   the FADT's CENTURY names, none when it names none. A machine without the
//!   chip whose firmware does not say so leaves the ports floating, and the
//!   driver says "no device" on its first read.
//! * boards (Kconfig `DRV_RTC_PCF8563`): a PCF8563 on I2C bus
//!   `RTC_PCF8563_I2C_BUS`, looked for by [`install_i2c`] once the I2C
//!   controllers are up.
//!
//! # Seeding
//!
//! [`install`] reads the chip once. A time that fails the chip's own integrity
//! check (a dead battery, a stopped oscillator) or is before Kconfig
//! `RTC_FLOOR_YEAR` (a battery reset to 2000, a chip nobody ever set) is
//! reported and **not used**: the wall clock stays unset until a reference
//! sets it, and the reference's step writes the chip back. Any other time
//! becomes the wall clock (`azos_syscall::clock::seed_wall`, a recorded step),
//! before the network is up, so the records of the boot carry a date.
//!
//! # Setting
//!
//! A set is an effect of kind `KIND_CLOCK`: with the write-ahead gate
//! (Kconfig `EFFECT_WRITE_AHEAD`) its record is committed before the chip is
//! written. The subject is [`SUBJECT_RTC`]; the SoC frameworks' subjects are
//! `provider << 8 | op` with a small provider index, so provider 0xff is never
//! theirs. `a0` is the clock (`ClockId::REAL`) and `a1` the seconds, saturated
//! to 32 bits like every effect's value.

use azos_rtc::civil::{year_start, DateTime};
use azos_rtc::{Error, Rtc};
use azos_sync::SpinLock;
use azos_syscall::clock::{RtcFault, RtcHost};

use crate::kprintln;

/// The gate's subject for the RTC (see the module doc).
#[cfg(feature = "effect-gate")]
pub(crate) const SUBJECT_RTC: u16 = 0xff00;

// ── The kernel's side of the drivers: the windows, the ports, the bus ────────

/// Volatile 32-bit accesses to a window [`probe_mmio`] mapped (identity: VA = PA).
#[cfg(not(target_arch = "x86_64"))]
struct Window(usize);

#[cfg(not(target_arch = "x86_64"))]
impl azos_rtc::Mmio for Window {
    fn read32(&mut self, off: u32) -> u32 {
        // SAFETY: inside the 4 KiB window `probe_mmio` mapped; every register
        // the drivers name is 4-aligned.
        unsafe { azos_arch_api::mmio::read32(self.0 + off as usize) }
    }
    fn write32(&mut self, off: u32, v: u32) {
        // SAFETY: as `read32`.
        unsafe { azos_arch_api::mmio::write32(self.0 + off as usize, v) }
    }
}

/// The PC's I/O ports.
#[cfg(target_arch = "x86_64")]
struct PcPorts;

#[cfg(target_arch = "x86_64")]
impl azos_rtc::Ports for PcPorts {
    fn inb(&mut self, port: u16) -> u8 {
        azos_arch::cpu::inb(port)
    }
    fn outb(&mut self, port: u16, v: u8) {
        azos_arch::cpu::outb(port, v)
    }
}

/// One I2C bus, through the controller driver's register transfers.
#[cfg(feature = "rtc-pcf8563")]
struct KernelI2c(u8);

#[cfg(feature = "rtc-pcf8563")]
impl azos_rtc::I2c for KernelI2c {
    fn read_regs(&mut self, addr: u8, reg: u8, buf: &mut [u8]) -> Result<(), Error> {
        if azos_drv_bus::i2c::i2c_read(self.0, addr, reg, buf) as isize == buf.len() as isize {
            Ok(())
        } else {
            Err(Error::Bus)
        }
    }
    fn write_regs(&mut self, addr: u8, data: &[u8]) -> Result<(), Error> {
        if azos_drv_bus::i2c::i2c_write(self.0, addr, data) >= 0 { Ok(()) } else { Err(Error::Bus) }
    }
}

// ── The one chip ─────────────────────────────────────────────────────────────

enum Chip {
    #[cfg(not(target_arch = "x86_64"))]
    Goldfish(azos_rtc::goldfish::Goldfish<Window>),
    #[cfg(not(target_arch = "x86_64"))]
    Pl031(azos_rtc::pl031::Pl031<Window>),
    #[cfg(target_arch = "x86_64")]
    Cmos(azos_rtc::mc146818::Mc146818<PcPorts>),
    #[cfg(feature = "rtc-pcf8563")]
    Pcf8563(azos_rtc::pcf8563::Pcf8563<KernelI2c>),
}

impl Chip {
    fn rtc(&mut self) -> &mut dyn Rtc {
        match self {
            #[cfg(not(target_arch = "x86_64"))]
            Chip::Goldfish(c) => c,
            #[cfg(not(target_arch = "x86_64"))]
            Chip::Pl031(c) => c,
            #[cfg(target_arch = "x86_64")]
            Chip::Cmos(c) => c,
            #[cfg(feature = "rtc-pcf8563")]
            Chip::Pcf8563(c) => c,
        }
    }
}

fn fault(e: Error) -> RtcFault {
    match e {
        Error::Lost => RtcFault::Lost,
        Error::Range => RtcFault::Range,
        Error::Bus | Error::NoDevice => RtcFault::Bus,
    }
}

/// The board's RTC. Interrupts off while it is held: the chip is reached from
/// the boot, from the discipline's write-back (a task) and from the `Clock`
/// op, and a CMOS read or an I2C transfer must not be interleaved with another.
struct Host(SpinLock<Option<Chip>>);

static HOST: Host = Host(SpinLock::new(None));

impl RtcHost for Host {
    fn read(&self) -> Result<u64, RtcFault> {
        match self.0.lock_irqsave().as_mut() {
            Some(chip) => chip.rtc().read().map_err(fault),
            None => Err(RtcFault::Bus),
        }
    }

    fn set(&self, unix_secs: u64, tid: u32) -> Result<(), RtcFault> {
        let write = || match self.0.lock_irqsave().as_mut() {
            Some(chip) => chip.rtc().set(unix_secs).map_err(fault),
            None => Err(RtcFault::Bus),
        };
        #[cfg(feature = "effect-gate")]
        {
            use azos_actuation::effect_gate::{self as gate, Class, Effect, Timing, KIND_CLOCK};
            let e = Effect {
                kind: KIND_CLOCK,
                class: Class::Reversible,
                subject: SUBJECT_RTC,
                tid,
                a0: azos_abi::time::ClockId::REAL.raw(),
                a1: unix_secs.min(u32::MAX as u64) as u32,
            };
            gate::issue(&e, &Timing::NONE, || {
                let r = write();
                let ok = r.is_ok();
                (r, ok)
            })
            .map_err(|_| RtcFault::Refused)?
        }
        #[cfg(not(feature = "effect-gate"))]
        {
            let _ = tid;
            write()
        }
    }
}

// ── Finding it ───────────────────────────────────────────────────────────────

/// The first hardware-bus device `selector` names, and its window mapped for
/// the kernel: `(base, size)`.
#[cfg(not(target_arch = "x86_64"))]
fn probe_mmio(selector: &str) -> Option<usize> {
    use azos_drv_bus::hwbus::{self, Handle};
    let h = hwbus::resolve(selector)?;
    let (base, size) = hwbus::with(|b| b.get(Handle(h)).map(|s| (s.dev.base, s.dev.size)))?;
    if size == 0 || !crate::boot::map_mmio_region(base as usize, size as usize) {
        return None;
    }
    Some(base as usize)
}

/// The chip this machine has, if any, and how it was found.
fn probe() -> Option<(Chip, &'static str)> {
    #[cfg(not(target_arch = "x86_64"))]
    {
        if let Some(base) = probe_mmio("dt:google,goldfish-rtc") {
            let c = azos_rtc::goldfish::Goldfish::new(Window(base));
            return Some((Chip::Goldfish(c), "dt:google,goldfish-rtc"));
        }
        if let Some(base) = probe_mmio("dt:arm,pl031") {
            return match azos_rtc::pl031::Pl031::probe(Window(base)) {
                Ok(c) => Some((Chip::Pl031(c), "dt:arm,pl031")),
                Err(_) => {
                    azos_drv_sys::kwarn!("[RTC] the arm,pl031 window answers as no PL031: RTC not used");
                    None
                }
            };
        }
        None
    }
    #[cfg(target_arch = "x86_64")]
    {
        // The FADT says whether there is a chip and where its century is.
        // Without a FADT (no ACPI) the ports are tried: a machine without a
        // CMOS clock leaves them floating, and the driver tells that bus from
        // a chip on its first read (status D reads 0xff where no chip does).
        let fadt = azos_arch::platform_impl::platform().acpi.fadt;
        if fadt.is_some_and(|f| f.no_cmos_rtc()) {
            kprintln!("[RTC] the FADT says there is no CMOS RTC (IAPC_BOOT_ARCH bit 5)");
            return None;
        }
        // The pair is the kernel's (the index port's bit 7 also masks the
        // NMI): no ring-3 grant may open it.
        azos_arch::ioport::reserve(azos_rtc::mc146818::PORT_INDEX, azos_rtc::mc146818::PORT_DATA);
        let c = azos_rtc::mc146818::Mc146818::new(
            PcPorts,
            fadt.and_then(|f| f.century_register()),
            azos_limits::RTC_UIP_POLLS as u32,
        );
        Some((Chip::Cmos(c), "ports 0x70/0x71"))
    }
}

// ── Bringing it up ───────────────────────────────────────────────────────────

/// `YYYY-MM-DDTHH:MM:SSZ` for the boot line.
struct Utc(u64);

impl core::fmt::Display for Utc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match DateTime::from_epoch(self.0) {
            Some(t) => write!(f, "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", t.year, t.month, t.day, t.hour, t.min, t.sec),
            None => write!(f, "@{}", self.0),
        }
    }
}

/// Install `chip`, read it, and seed the wall clock from it. One boot line.
fn bring_up(chip: Chip, via: &str) {
    *HOST.0.lock_irqsave() = Some(chip);
    azos_syscall::clock::install_rtc(&HOST);
    let name = HOST.0.lock_irqsave().as_mut().map_or("?", |c| c.rtc().name());
    let floor = year_start(azos_limits::RTC_FLOOR_YEAR as u16);
    match HOST.read() {
        Ok(t) if t >= floor => {
            if azos_syscall::clock::seed_wall(t) {
                kprintln!("[RTC] {} ({}): {}, the wall clock starts there", name, via, Utc(t));
            } else {
                kprintln!("[RTC] {} ({}): {}, the wall clock was already set", name, via, Utc(t));
            }
        }
        Ok(t) => azos_drv_sys::kwarn!(
            "[RTC] {} ({}): {} is before {} (RTC_FLOOR_YEAR): not used, the wall clock stays unset",
            name, via, Utc(t), azos_limits::RTC_FLOOR_YEAR),
        Err(e) => azos_drv_sys::kwarn!(
            "[RTC] {} ({}): no time ({:?}): the wall clock stays unset", name, via, e),
    }
}

/// Find the board's memory-mapped or port-mapped RTC, seed the wall clock from
/// it, and host the `Clock` interface's RTC ops. After the hardware bus
/// enumerated the machine and the boot's device windows can be mapped, before
/// the network (a reference that steps the clock writes the chip back).
pub(crate) fn install() {
    match probe() {
        Some((chip, via)) => bring_up(chip, via),
        // A board with the PCF8563 looks again in `install_i2c`.
        None if cfg!(feature = "rtc-pcf8563") => {}
        None => kprintln!("[RTC] none: the wall clock starts unset"),
    }
}

/// The PCF8563 on `RTC_PCF8563_I2C_BUS`, for a board without a memory-mapped
/// RTC. After the I2C controllers are initialised (`install_robot_hw`). A
/// board that already has an RTC keeps it.
#[cfg(feature = "rtc-pcf8563")]
pub(crate) fn install_i2c() {
    if HOST.0.lock_irqsave().is_some() {
        return;
    }
    let bus = azos_limits::RTC_PCF8563_I2C_BUS as u8;
    if !azos_drv_bus::i2c::i2c_detect(bus, azos_rtc::pcf8563::ADDR) {
        kprintln!("[RTC] nothing answers i2c.{}.{:#x}: the wall clock starts unset", bus, azos_rtc::pcf8563::ADDR);
        return;
    }
    let chip = Chip::Pcf8563(azos_rtc::pcf8563::Pcf8563::new(KernelI2c(bus)));
    bring_up(chip, "i2c");
}

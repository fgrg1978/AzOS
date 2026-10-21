// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SoC PCIe host-controller bring-up (S4): the part firmware does not do on
//! these boards, before [`crate::enumerate_tree`] can see a single function.
//!
//! Two controllers, one flow each in [`plda`] (StarFive JH7110, PLDA
//! XpressRICH, the VisionFive 2) and [`brcmstb`] (Broadcom BCM2712 root
//! complex that leads to the RP1 on the Raspberry Pi 5):
//!
//! 1. validate the inputs (no register is touched on a refusal),
//! 2. hold the endpoint in reset (PERST# asserted for `PERST_HOLD_US`) before
//!    anything is programmed, and put the controller in root-complex mode,
//! 3. program the outbound windows (CPU -> PCI, from DT `ranges`) and the
//!    inbound ones (PCI -> CPU, from DT `dma-ranges`),
//! 4. release PERST#, wait for the link, and refuse a link that stays down,
//! 5. hand back how config space is reached ([`ConfigAccess`], usable as a
//!    [`ConfigSpace`] through [`ConfigPort`]), the windows for
//!    [`crate::resolve_bar_window`], and where MSIs land ([`MsiHookup`]).
//!
//! Register access goes through [`Bus`], so the sequence host-tests against a
//! trace of reads, writes and delays. Clocks, resets, PHY and regulators are
//! the platform glue's (clock/reset framework) and are done before `init`.
//! The sequences follow the public Linux drivers (`pcie-brcmstb.c`,
//! `plda/pcie-plda*.{c,h}`, `plda/pcie-starfive.c`); what the sources did not
//! settle is marked `[verify]` and waits for the board.

use core::cell::Cell;

use crate::{ecam_function_offset, Bdf, ConfigSpace, FirmwareWindows, HostWindow};

pub mod brcmstb;
pub mod dt;
pub mod plda;

/// Which register block an access goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Region {
    /// The controller's own registers (DT `reg` "apb"; the brcmstb block).
    Apb,
    /// The ECAM-shaped configuration window (DT `reg` "cfg"), PLDA only.
    Cfg,
    /// The SoC syscon the controller's mode and link status live in (the
    /// JH7110 STG block), PLDA only.
    Stg,
}

/// Register access and time, as the kernel provides them: volatile MMIO at
/// the mapped regions, a busy wait or a sleep for `delay_us`. `&self` like
/// [`ConfigSpace::read32`]: MMIO needs no exclusive borrow, and that is what
/// lets [`ConfigPort`] implement the trait.
pub trait Bus {
    fn read32(&self, region: Region, off: u32) -> u32;
    fn write32(&self, region: Region, off: u32, val: u32);
    fn delay_us(&self, us: u32);
}

/// The endpoint reset line when it is a GPIO and not a controller bit (the
/// VisionFive 2). `true` asserts PERST# (the endpoint is held in reset).
pub trait Perst {
    fn set_perst(&self, asserted: bool);
}

/// Which memory window of the host bridge a `ranges` entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemSpace {
    /// DT space code `10`.
    Mem32,
    /// DT space code `11`.
    Mem64,
}

/// One outbound window: a DT `ranges` entry (`HostWindow` carries the CPU
/// base, the PCI bus base and the size).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboundWindow {
    pub space: MemSpace,
    pub window: HostWindow,
}

/// One inbound window: a DT `dma-ranges` entry. A device behind the bridge
/// that emits PCI address `[bus_base, bus_base + size)` reaches CPU memory at
/// `cpu_base`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InboundWindow {
    pub bus_base: u64,
    pub cpu_base: u64,
    pub size: u64,
}

/// Why a controller was not brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostError {
    /// Outbound window `n` cannot be programmed (size, alignment, reach).
    BadOutbound(usize),
    /// Inbound window `n` cannot be programmed.
    BadInbound(usize),
    /// More outbound windows than the controller has translation entries.
    TooManyOutbound,
    /// More inbound windows than the controller has.
    TooManyInbound,
    /// The configuration window (PLDA `cfg`) is not a power of two the
    /// translation entry can express.
    BadConfigWindow,
    /// The MSI doorbell bus address cannot be put in IMSI_ADDR (above 4 GiB
    /// or not dword-aligned).
    BadMsiDoorbell,
    /// The controller reports endpoint mode (brcmstb status port bit clear).
    NotRootComplex,
    /// A PHY (MDIO) write was not acknowledged.
    MdioTimeout,
    /// The link did not come up. PERST# was asserted again; nothing is to be
    /// enumerated behind this controller.
    LinkDown { waited_us: u32 },
}

/// How configuration space is reached after `init`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigAccess {
    /// The [`Region::Cfg`] window is ECAM-shaped: function `bdf`'s register
    /// `off` is at `ecam_function_offset(bdf) + off`. `size` is the mapped
    /// window's length in bytes; a function whose register would fall past it
    /// (a bus beyond the window) is unreachable, never an access outside the
    /// mapping.
    Ecam { size: u64 },
    /// Indirect (brcmstb): bus 0 is the root complex itself, reached directly
    /// in [`Region::Apb`] (device 0 function 0 only). Any other bus is reached
    /// by writing `ecam_function_offset(bdf)` to `index_off` and accessing the
    /// register at `data_off + off`; the link is point to point, so the bus
    /// right behind the root complex answers for device 0 only.
    Indirect { index_off: u32, data_off: u32 },
}

/// Where the controller delivers MSIs, for the interrupt layer. The host
/// controller only decodes the doorbell; vector allocation, masking and the
/// summary interrupt belong to the irqchip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsiHookup {
    /// PCI bus address endpoints write to.
    pub doorbell: u64,
    /// The data an endpoint writes for vector 0; vector `n` is `data_base + n`.
    pub data_base: u32,
    pub vectors: u32,
    /// [`Region::Apb`] offset of the pending-vector register.
    pub status_off: u32,
    /// Offset the pending bits are acknowledged at (write 1 to clear).
    pub ack_off: u32,
    /// A controller-level summary bit to acknowledge before reading
    /// `status_off`: `(register offset, mask)`; `None` when the MSI block has
    /// its own interrupt.
    pub summary: Option<(u32, u32)>,
}

/// What a successful `init` leaves the caller with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostReport {
    pub config: ConfigAccess,
    /// The memory windows, in the form [`crate::resolve_bar_window`] takes.
    pub windows: FirmwareWindows,
    pub msi: Option<MsiHookup>,
    /// How long the link took to come up after the fixed settle delay.
    pub link_wait_us: u32,
}

/// The first window of each space, as the BAR allocator wants them.
pub fn firmware_windows(outbound: &[OutboundWindow]) -> FirmwareWindows {
    let first = |s| outbound.iter().find(|w| w.space == s).map(|w| w.window);
    FirmwareWindows { mem32: first(MemSpace::Mem32), mem64: first(MemSpace::Mem64) }
}

// ---------------------------------------------------------------------
// Config access
// ---------------------------------------------------------------------

/// Config space of a brought-up controller, as a [`ConfigSpace`].
pub struct ConfigPort<'a, B: Bus> {
    bus: &'a B,
    access: ConfigAccess,
}

impl<'a, B: Bus> ConfigPort<'a, B> {
    pub fn new(bus: &'a B, access: ConfigAccess) -> Self {
        ConfigPort { bus, access }
    }

    /// `true` when `bdf` can be addressed through this controller at all.
    fn reachable(&self, bdf: Bdf, offset: u16) -> bool {
        if offset >= 4096 {
            return false;
        }
        match self.access {
            ConfigAccess::Ecam { size } => ecam_function_offset(bdf) as u64 + offset as u64 + 4 <= size,
            ConfigAccess::Indirect { .. } => match bdf.bus {
                0 => bdf.device == 0 && bdf.function == 0,
                1 => bdf.device == 0,
                _ => true,
            },
        }
    }
}

impl<B: Bus> ConfigSpace for ConfigPort<'_, B> {
    fn read32(&self, bdf: Bdf, offset: u16) -> u32 {
        if !self.reachable(bdf, offset) {
            return 0xffff_ffff;
        }
        match self.access {
            ConfigAccess::Ecam { .. } => self.bus.read32(Region::Cfg, ecam_function_offset(bdf) as u32 + offset as u32),
            ConfigAccess::Indirect { index_off, data_off } => {
                if bdf.bus == 0 {
                    return self.bus.read32(Region::Apb, offset as u32);
                }
                self.bus.write32(Region::Apb, index_off, ecam_function_offset(bdf) as u32);
                self.bus.read32(Region::Apb, data_off + offset as u32)
            }
        }
    }

    fn write32(&mut self, bdf: Bdf, offset: u16, val: u32) {
        if !self.reachable(bdf, offset) {
            return;
        }
        match self.access {
            ConfigAccess::Ecam { .. } => self.bus.write32(Region::Cfg, ecam_function_offset(bdf) as u32 + offset as u32, val),
            ConfigAccess::Indirect { index_off, data_off } => {
                if bdf.bus == 0 {
                    return self.bus.write32(Region::Apb, offset as u32, val);
                }
                self.bus.write32(Region::Apb, index_off, ecam_function_offset(bdf) as u32);
                self.bus.write32(Region::Apb, data_off + offset as u32, val);
            }
        }
    }
}

// ---------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------

/// Read-modify-write: the bits of `mask` become `val & mask`.
pub(crate) fn update_bits<B: Bus>(bus: &B, region: Region, off: u32, mask: u32, val: u32) {
    let cur = bus.read32(region, off);
    bus.write32(region, off, (cur & !mask) | (val & mask));
}

/// `log2(x)` when `x` is a power of two.
pub(crate) fn log2_exact(x: u64) -> Option<u32> {
    (x != 0 && x & (x - 1) == 0).then(|| x.trailing_zeros())
}

/// Wait for the link: `up` is checked, then `step_us` is waited, `checks`
/// times, and once more at the end (the Linux loops do the same). `Ok` holds
/// the time waited when the link was seen up.
pub(crate) fn wait_link<B: Bus>(bus: &B, checks: u32, step_us: u32, up: impl Fn() -> bool) -> Result<u32, u32> {
    let waited = Cell::new(0u32);
    for _ in 0..checks {
        if up() {
            return Ok(waited.get());
        }
        bus.delay_us(step_us);
        waited.set(waited.get().saturating_add(step_us));
    }
    if up() {
        Ok(waited.get())
    } else {
        Err(waited.get())
    }
}

/// Number of link checks for a timeout.
pub(crate) fn checks_for(timeout_us: u32, step_us: u32) -> u32 {
    timeout_us.div_ceil(step_us)
}

/// PCIe spec / Linux `drivers/pci/pci.h`: PERST# stays asserted at least
/// this long after power is stable (`PCIE_T_PVPERL_MS`).
pub(crate) const PERST_HOLD_US: u32 = 100_000;
/// Time after PERST# release before the first config access
/// (`PCIE_RESET_CONFIG_WAIT_MS`).
pub(crate) const RESET_CONFIG_WAIT_US: u32 = 100_000;

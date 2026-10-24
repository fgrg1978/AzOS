// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Raspberry Pi VideoCore mailbox (kernel feature `rpi-firmware`): the
//! power of the SoC's blocks goes through it ([`power_on`], the USB host's
//! before its probe), and with `energy` it is the board object of the energy
//! apply step and the thermal task: the temperature of the SoC and the ARM
//! clock (`azos_thermal::rpi`).
//! aarch64-only: the Pi boards are the only ones with this firmware, and the
//! cache maintenance of the message buffer is the ISA's.
//!
//! The kernel maps its image in the high half, so the buffer's bus address is
//! its physical address (`virt_to_phys`) with the VideoCore's alias, and the
//! buffer is cleaned before the firmware reads it and invalidated before the
//! CPU reads the answer. The port is `azos_firmware::MmioPort` (registers,
//! bus window and the refusal of a buffer the window does not map); this file
//! supplies only what is the kernel's: the translation and the cache
//! maintenance (`Hooks`). The window is decided from the SoC the device tree
//! names (the Pi 5's is the identity map, the older Pis' the 0xC000_0000
//! alias), so a board whose bus map is not known never gets the firmware's
//! DMA.
//!
//! The energy step brings the mailbox up ([`energy_model`]): the Pi's OPP table
//! is the firmware's clock range, so the mailbox is enabled and the clock
//! probed before the model is resolved, and the thermal runtime built after it
//! only reads what was probed.

use azos_firmware::{BusWindow, DmaHooks, Mailbox, MailboxError, MmioPort};
use azos_sync::SpinLock;
#[cfg(feature = "energy")]
use azos_thermal::rpi::RpiFirmware;
use core::sync::atomic::{AtomicUsize, Ordering};

/// The kernel's half of the mailbox port: the high-half translation and the
/// ISA's cache maintenance of the message buffer. The registers and the bus
/// window are `azos_firmware::MmioPort`'s.
pub(crate) struct Hooks;

impl DmaHooks for Hooks {
    fn phys(&self, buf: *const u8) -> u64 {
        azos_mm::addr::virt_to_phys(buf as usize) as u64
    }
    fn clean(&mut self, buf: *mut u8, len: usize) {
        // SAFETY: `buf` is the mailbox's own buffer, `len` bytes of it.
        unsafe { azos_arch::cache::dcache_clean(buf as usize, len) };
    }
    fn invalidate(&mut self, buf: *mut u8, len: usize) {
        // SAFETY: as `clean`; clean-and-invalidate cannot lose a write the
        // CPU has not made.
        unsafe { azos_arch::cache::dcache_clean_and_invalidate(buf as usize, len) };
    }
}

type Port = MmioPort<Hooks>;

/// What holds the mailbox: the thermal task's board object around it, or the
/// mailbox alone. Either way there is one, so the power requests and the
/// thermal ones never share the channel from two buffers.
#[cfg(feature = "energy")]
type Board = RpiFirmware<Port>;
#[cfg(not(feature = "energy"))]
type Board = Mailbox<Port>;

#[cfg(feature = "energy")]
fn board(m: Mailbox<Port>) -> Board {
    RpiFirmware::new(m)
}
#[cfg(not(feature = "energy"))]
fn board(m: Mailbox<Port>) -> Board {
    m
}

#[cfg(feature = "energy")]
fn mailbox(b: &mut Board) -> &mut Mailbox<Port> {
    &mut b.mbox
}
#[cfg(not(feature = "energy"))]
fn mailbox(b: &mut Board) -> &mut Mailbox<Port> {
    b
}

/// The mailbox, where it is built and where it stays: the firmware writes its
/// answers into the buffer inside, so it must not move once a call has given
/// up (`azos_firmware::Mailbox`).
static RPI: SpinLock<Option<Board>> = SpinLock::new(None);

/// The register window the hwbus probe bound; 0 until it did.
static BASE: AtomicUsize = AtomicUsize::new(0);

/// The `brcm,bcm2835-mbox` node's probe: keep the window. The firmware's DMA
/// stays off until [`enable`] knows the board's bus map: the node is the same
/// on every Pi, the maps differ, and a buffer posted at the wrong bus address
/// is written by the VideoCore over someone else's memory.
pub(crate) fn attach(base: usize) {
    BASE.store(base, Ordering::Release);
}

/// Did the probe bind a mailbox node?
#[cfg(feature = "energy")]
pub(crate) fn attached() -> bool {
    BASE.load(Ordering::Acquire) != 0
}

/// Turn the mailbox on for the SoC whose root `compatible` is `root` (the
/// device tree's NUL-separated strings). `false` (and the mailbox stays off,
/// so no power request, no sensor and no ARM clock) when the SoC's bus map is
/// not one `azos_firmware::BusWindow` knows, or no window was bound. A
/// mailbox already on stays as it is.
pub(crate) fn enable(root: &[u8]) -> bool {
    let base = BASE.load(Ordering::Acquire);
    let Some(window) = BusWindow::for_root_compatible(root) else { return false };
    if base == 0 {
        return false;
    }
    let mut rpi = RPI.lock();
    if rpi.is_some() {
        return true;
    }
    // SAFETY: `base` is the window `attach` was given, mapped as device
    // memory by the probe; the mailbox lives in the `RPI` static, in kernel
    // memory, and `bus_addr` checks its physical address against `window`
    // for every message.
    let port = unsafe { MmioPort::new(base, window, Hooks) };
    *rpi = Some(board(Mailbox::new(port)));
    true
}

/// Power on the firmware's device `device` (`azos_firmware::POWER_DEVICE_*`),
/// waiting until it is, on the SoC whose root `compatible` is `root`: the
/// mailbox is turned on first ([`enable`]) if the energy step has not yet.
/// `Err(None)` when no mailbox can be used (none bound, or a SoC whose bus
/// map is unknown), `Err(Some(e))` when the firmware refused or has no such
/// device.
pub(crate) fn power_on(root: &[u8], device: u32) -> Result<(), Option<MailboxError>> {
    if !enable(root) {
        return Err(None);
    }
    RPI.lock().as_mut().map_or(Err(None), |b| mailbox(b).power_on(device).map_err(Some))
}

/// Run `f` on the board object, in place, under its lock. `None` when the
/// mailbox is not enabled. (The gate row's fake board replaces it.)
#[cfg(feature = "energy")]
#[cfg_attr(feature = "thermal-smoke", allow(dead_code))]
pub(crate) fn with<R>(f: impl FnOnce(&mut RpiFirmware<Port>) -> R) -> Option<R> {
    RPI.lock().as_mut().map(f)
}

/// Bring the mailbox up for the SoC the tree at `dtb_ptr` names ([`enable`]),
/// probe the ARM clock and return the energy model its range makes
/// (`RpiFirmware::energy_model`: placeholder power, unmeasured). The energy
/// step's, once, before the model is resolved and before the thermal runtime
/// is built. `None` when no mailbox node was bound, its SoC's bus map is not
/// known, or the firmware gave no range that can move (QEMU `raspi`): the
/// line says which, and the thermal runtime then has the sensor alone.
#[cfg(feature = "energy")]
#[cfg_attr(feature = "thermal-smoke", allow(dead_code))]
pub(crate) fn energy_model(
    dtb_ptr: usize,
    num_cpus: usize,
) -> Option<Result<azos_energy::EnergyModel, azos_energy::ModelFault>> {
    if !attached() || dtb_ptr == 0 {
        return None;
    }
    // SAFETY: the firmware's blob, parsed before by `early_main`.
    let info = unsafe { azos_dtb::dtb_parse(azos_mm::addr::phys_to_virt(dtb_ptr) as *const u8) }?;
    if !enable(&info.compatible) {
        crate::kprintln!("[ENERGY] rpi: a mailbox on a SoC whose VideoCore bus map is unverified: the firmware stays off");
        return None;
    }
    with(|fw| {
        match fw.probe_clock() {
            Ok(c) => crate::kprintln!("[ENERGY] rpi: ARM clock {}..{} kHz from the firmware", c.min_hz / 1000, c.max_hz / 1000),
            Err(e) => azos_drv_sys::kwarn!("[ENERGY] rpi: no ARM clock range the firmware lets us move ({:?}): no OPP table from it", e),
        }
        fw.energy_model(num_cpus)
    })
    .flatten()
}

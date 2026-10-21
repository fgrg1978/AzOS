// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kconfig SOC_FRAMEWORKS (kernel feature `soc`): the clock, reset, regulator,
//! power-domain and pad-controller managers of `azos_soc`, built from the device tree at
//! boot.
//!
//! One heap allocation holds the providers (`azos_soc::boot::Storage`, leaked:
//! the managers borrow it for good); the managers sit behind one lock. The
//! register windows of the providers that have registers are mapped here (a
//! provider whose window the mapping refused is dropped, never used), the
//! always-on rails are switched on, and the boot line says what was found.
//! Nothing is written to hardware at boot: the registers are touched by the
//! first consumer.
//!
//! **The consumer is the hardware bus's bind.** [`bind`] (`azos_soc::bind`)
//! gives a device what its node names: power domains, `assigned-clock-rates`,
//! clocks, resets, then the `default` pin state; [`unbind`] takes it back. The
//! bus calls them through `Drivers::resources` / `release`
//! (`kernel/src/boot/hwbus.rs`) for a native driver bound to a device that
//! carries a tree node (`Device::dt_node`), before the driver is asked and
//! after it let go. Nothing else is a consumer: the record-only hardware (the
//! console, the interrupt controllers, these controllers) is up before the
//! frameworks are, and a node whose driver is a ring-3 server or the Linux
//! slice asks through its device interface. There is no boot-time pass over
//! the tree. [`with`] remains the door for the one other reader, the
//! introspection tree's `soc/`.
//!
//! **Every change is a write-ahead effect.** [`GateSink`] is the managers'
//! effect sink: it hands each change to the effect gate
//! (`azos_actuation::effect_gate::record`), which commits its record to the
//! flight recorder's ring before the manager writes its register, and refuses
//! a change the ring cannot hold unless it moves toward quiescence. That is why
//! the feature needs `effect-gate` (Kconfig EFFECT_WRITE_AHEAD).
//!
//! The device windows the JH7110 controllers sit in are claimed by the
//! hardware bus as the kernel's (`crates/drivers/soc/hwbus.ids`, driver
//! `soc`), so ring 3 is never handed one.

use crate::kprintln;
use alloc::boxed::Box;
use azos_actuation::effect_gate as gate;
use azos_soc::boot::{Families, Soc, Storage};
use azos_soc::regulator::Io;
use azos_soc::{effect, Bus, Effect, EffectSink, Fdt, Refused};

// The numbers the gate reserves are the ones the frameworks put on the wire.
const _: () = {
    assert!(gate::KIND_CLOCK == effect::KIND_CLOCK);
    assert!(gate::KIND_RESET == effect::KIND_RESET);
    assert!(gate::KIND_REGULATOR == effect::KIND_REGULATOR);
    assert!(gate::KIND_PINCTRL == effect::KIND_PINCTRL);
    assert!(gate::KIND_POWER_DOMAIN == effect::KIND_POWER_DOMAIN);
};

/// The largest device tree the kernel reads (`azos_dtb`'s own bound).
const MAX_DTB: usize = 4 * 1024 * 1024;

/// Register access at a physical address. The provider windows are mapped
/// 1:1 by [`install`], as every device window is.
struct Mmio;

impl Bus for Mmio {
    fn read32(&mut self, addr: u64) -> u32 {
        // SAFETY: `addr` is inside a provider window `install` mapped as
        // device memory; the providers keep their offsets word-aligned.
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }
    fn write32(&mut self, addr: u64, val: u32) {
        // SAFETY: as `read32`.
        unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
    }
}

/// The managers' effect sink: the write-ahead gate, on behalf of the kernel
/// (task 0). Also the sink of the K1's rail steps, which are made outside the
/// frameworks' lock (`boot::thermal`).
pub(crate) struct GateSink;

impl EffectSink for GateSink {
    fn commit(&mut self, e: &Effect) -> Result<(), Refused> {
        let (kind, subject, a0, a1) = e.wire();
        let class = match e.class {
            effect::Class::Safe => gate::Class::Safe,
            effect::Class::Reversible => gate::Class::Reversible,
        };
        gate::record(&gate::Effect { kind, class, subject, tid: 0, a0, a1 })
            .map_err(|r| Refused { receipt: r.receipt })
    }
}

struct State {
    soc: Soc<'static>,
    /// The device tree the providers were read from; the kernel keeps it.
    blob: &'static [u8],
}

// SAFETY: the providers hold register addresses and plain data, no pointer
// into a thread; every access to the state is under the lock below.
unsafe impl Send for State {}

static SOC: azos_sync::SpinLock<Option<State>> = azos_sync::SpinLock::new(None);

/// Build the frameworks from the device tree at `dtb_ptr`. After the hardware
/// bus enumerated the tree (its `soc` ids are bound to the same nodes), before
/// any driver that would ask for a clock.
pub(crate) fn install(dtb_ptr: usize) {
    if dtb_ptr == 0 {
        kprintln!("[SOC] no device tree: no frameworks");
        return;
    }
    let base = azos_mm::addr::phys_to_virt(dtb_ptr) as *const u8;
    // SAFETY: the firmware handed the kernel this pointer and `early_main`
    // already parsed the header; the first eight bytes are the magic and the
    // total size, and the whole blob is bounded by that size below.
    let total = unsafe { core::slice::from_raw_parts(base.add(4), 4) };
    let total = u32::from_be_bytes([total[0], total[1], total[2], total[3]]) as usize;
    if !(40..=MAX_DTB).contains(&total) {
        azos_drv_sys::kwarn!("[SOC] the device tree size {} is not readable: no frameworks", total);
        return;
    }
    // SAFETY: `total` bytes from the header's own size field.
    let blob: &'static [u8] = unsafe { core::slice::from_raw_parts(base, total) };
    let Some(fdt) = Fdt::parse(blob) else {
        azos_drv_sys::kwarn!("[SOC] the device tree is not readable: no frameworks");
        return;
    };
    let storage: &'static mut Storage = Box::leak(Box::new(Storage::new()));
    storage.scan(&fdt, Families { jh7110: cfg!(feature = "soc-jh7110"), k1: cfg!(feature = "soc-k1") });
    // A provider whose window is not mapped is dropped: reading its registers
    // would be a kernel fault.
    let win = storage.map_windows(&fdt, |base, size| crate::boot::map_mmio_region(base as usize, size as usize));
    if win.failed != 0 {
        azos_drv_sys::kwarn!("[SOC] {} register window(s) not mapped: their providers are not used", win.failed);
    }
    // The K1's PMIC rails are reached over its I2C master, which attaches
    // after the frameworks come up (`install_robot_hw`): the transport is given
    // now so the rails are providers (`cpu-supply` resolves, with the rail's
    // constraints), and the always-on pass leaves them (`always-on-pending`:
    // the pass would read the PMIC under the lock). Other boards have no rail
    // behind a bus.
    #[cfg(all(feature = "k1", feature = "soc-k1"))]
    let mut pmic = super::hwbus::PmicI2c;
    #[cfg(all(feature = "k1", feature = "soc-k1"))]
    let i2c: Option<&mut dyn azos_soc::I2cBus> = Some(&mut pmic);
    #[cfg(not(all(feature = "k1", feature = "soc-k1")))]
    let i2c: Option<&mut dyn azos_soc::I2cBus> = None;
    let soc = Soc::build(storage, &fdt, &mut Io { bus: &mut Mmio, i2c }, &mut GateSink);
    let r = soc.report;
    match r.always_on {
        Ok(n) => kprintln!(
            "[SOC] clocks={} resets={} regulators={} domains={} pins={} always-on={} always-on-pending={} windows={} dropped={} no-transport={}",
            r.clocks, r.resets, r.regulators, r.domains, r.pin_controllers, n, r.always_on_pending, win.mapped, r.dropped, r.no_transport),
        Err(e) => azos_drv_sys::kwarn!(
            "[SOC] clocks={} resets={} regulators={} domains={} pins={} always-on rail refused: {:?} no-transport={}",
            r.clocks, r.resets, r.regulators, r.domains, r.pin_controllers, e, r.no_transport),
    }
    *SOC.lock() = Some(State { soc, blob });
}

/// Pin the PMIC's `regulator-always-on` rails, now that the I2C master they
/// are behind is attached (`install_robot_hw`): [`install`] left them pending
/// (`always-on-pending`) because the pass reads the PMIC, and a transfer is
/// hundreds of microseconds and sleeps between steps, which no spin lock may
/// be held across. So the state is taken out of the lock for the pass and put
/// back. Boot is single-threaded here (no task exists yet, the hardware bus's
/// binds are over), so nothing asks for the frameworks meanwhile; [`with`]
/// would answer `None` if something did.
#[cfg(all(feature = "k1", feature = "soc-k1"))]
pub(crate) fn pin_pmic_always_on() {
    let Some(mut st) = SOC.lock().take() else { return };
    if st.soc.report.always_on_pending != 0 {
        let mut pmic = super::hwbus::PmicI2c;
        st.soc.retry_always_on(&mut Io { bus: &mut Mmio, i2c: Some(&mut pmic) }, &mut GateSink);
        let r = st.soc.report;
        match r.always_on {
            Ok(n) => kprintln!("[SOC] always-on={} always-on-pending={} (PMIC rails pinned)", n, r.always_on_pending),
            Err(e) => azos_drv_sys::kwarn!(
                "[SOC] a PMIC always-on rail refused: {:?} (always-on-pending={})", e, r.always_on_pending),
        }
    }
    *SOC.lock() = Some(st);
}

/// Run `f` on the managers, the device tree, the register bus and the effect
/// sink, under the lock. `None` before [`install`] or when it found no tree.
pub(crate) fn with<R>(
    f: impl FnOnce(&Fdt<'_>, &mut Soc<'static>, &mut dyn Bus, &mut dyn EffectSink) -> R,
) -> Option<R> {
    let mut g = SOC.lock();
    let st = g.as_mut()?;
    let fdt = Fdt::parse(st.blob)?;
    Some(f(&fdt, &mut st.soc, &mut Mmio, &mut GateSink))
}

/// Give the device whose tree node is `node` its power domains, clock rates,
/// clocks, resets and `default` pin state; on an error nothing is left on.
/// Without frameworks (before [`install`], or no tree) there is nothing to
/// give and the device binds as it always did.
pub(crate) fn bind(node: u32) -> Result<azos_soc::bind::Applied, azos_soc::Error> {
    with(|fdt, soc, bus, fx| azos_soc::bind::bind(soc, fdt, bus, fx, azos_soc::NodeId(node)))
        .unwrap_or(Ok(azos_soc::bind::Applied::default()))
}

/// Take back what [`bind`] gave `node`.
pub(crate) fn unbind(node: u32) -> Result<(), azos_soc::Error> {
    with(|fdt, soc, bus, fx| azos_soc::bind::unbind(soc, fdt, bus, fx, azos_soc::NodeId(node))).unwrap_or(Ok(()))
}

/// The report's words, in the order of [`report_words`].
#[cfg(feature = "inspect")]
const REPORT: [&str; 9] = [
    "clocks", "resets", "regulators", "domains", "pin_controllers", "dropped", "no_transport", "always_on",
    "always_on_pending",
];

#[cfg(feature = "inspect")]
static TREE: azos_sync::SpinLock<Option<(azos_inspect::NodeId, [azos_inspect::NodeId; REPORT.len()])>> =
    azos_sync::SpinLock::new(None);

/// What the boot step registered, as the tree's words; `None` before it ran.
#[cfg(feature = "inspect")]
fn report_words() -> Option<[u64; REPORT.len()]> {
    with(|_fdt, soc, _bus, _fx| {
        let r = soc.report;
        [
            r.clocks, r.resets, r.regulators, r.domains, r.pin_controllers, r.dropped, r.no_transport,
            r.always_on.unwrap_or(0), r.always_on_pending,
        ]
        .map(|v| v as u64)
    })
}

/// `soc/{up, clocks, resets, regulators, domains, pin_controllers, dropped,
/// no_transport, always_on, always_on_pending}`: what the boot step
/// registered, for the board bring-up (`up` is 0 before it ran). It reads the
/// report kept at boot and touches no register.
#[cfg(feature = "inspect")]
pub(crate) fn inspect_build(
    b: &mut azos_inspect::Builder<'_, '_>,
    root: azos_inspect::NodeId,
) -> Result<(), azos_inspect::Error> {
    let d = b.dir(root, "soc")?;
    let up = b.u64(d, "up", 0)?;
    let mut ids = [azos_inspect::NodeId::ROOT; REPORT.len()];
    for (id, name) in ids.iter_mut().zip(REPORT) {
        *id = b.u64(d, name, 0)?;
    }
    *TREE.lock_irqsave() = Some((up, ids));
    Ok(())
}

/// Rewrite the report; the values that were not published.
#[cfg(feature = "inspect")]
pub(crate) fn inspect_refresh(w: &azos_inspect::Writer<'_>) -> u32 {
    let Some((up, ids)) = *TREE.lock_irqsave() else { return 0 };
    let words = report_words();
    let mut bad = w.set_u64(up, words.is_some() as u64).is_err() as u32;
    for (id, v) in ids.iter().zip(words.unwrap_or_default()) {
        bad += w.set_u64(*id, v).is_err() as u32;
    }
    bad
}

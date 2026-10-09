// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The IOAPICs: one redirection entry per GSI (vector = `IRQ_VECTOR_BASE` +
//! GSI, physical destination APIC ID, trigger and polarity). The chips come
//! from the MADT (or Kconfig `X86_IOAPIC_FALLBACK_BASE` at GSI 0 without
//! one); [`init`] masks every pin. A line stays masked until a driver or a
//! ring-3 owner binds it.

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use crate::acpi::MAX_IOAPICS;
use crate::encode::{self, IOAPIC_REGSEL, IOAPIC_WIN, RTE_MASKED};
use crate::platform_impl::platform;

struct Chip {
    base: AtomicUsize,
    gsi_base: AtomicU32,
    pins: AtomicU32,
}

static CHIPS: [Chip; MAX_IOAPICS] = [const {
    Chip { base: AtomicUsize::new(0), gsi_base: AtomicU32::new(0), pins: AtomicU32::new(0) }
}; MAX_IOAPICS];
static N_CHIPS: AtomicUsize = AtomicUsize::new(0);
/// IOREGSEL/IOWIN is a two-step access: one CPU at a time.
static LOCK: AtomicBool = AtomicBool::new(false);

struct Guard(u64);

fn lock() -> Guard {
    let f = crate::hw::rflags();
    crate::hw::cli();
    while LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
    Guard(f)
}

impl Drop for Guard {
    fn drop(&mut self) {
        LOCK.store(false, Ordering::Release);
        if self.0 & crate::hw::RFLAGS_IF != 0 {
            crate::hw::sti();
        }
    }
}

fn reg_read(base: usize, reg: u32) -> u32 {
    // SAFETY: the chip's IOREGSEL/IOWIN, mapped by `kernel_mmio_windows`;
    // callers hold LOCK.
    unsafe {
        core::ptr::write_volatile((base + IOAPIC_REGSEL) as *mut u32, reg);
        core::ptr::read_volatile((base + IOAPIC_WIN) as *const u32)
    }
}

fn reg_write(base: usize, reg: u32, v: u32) {
    // SAFETY: as `reg_read`.
    unsafe {
        core::ptr::write_volatile((base + IOAPIC_REGSEL) as *mut u32, reg);
        core::ptr::write_volatile((base + IOAPIC_WIN) as *mut u32, v);
    }
}

/// Each IOAPIC's (MMIO base, page count 1): for the kernel's device map.
pub fn for_each_window(mut f: impl FnMut(usize)) {
    let p = platform();
    match p.madt().filter(|m| m.n_ioapics != 0) {
        Some(m) => m.ioapics().iter().for_each(|io| f(io.addr as usize)),
        None => f(azos_limits::X86_IOAPIC_FALLBACK_BASE),
    }
}

/// Register every IOAPIC and mask all its pins (boot CPU, after the MMU is
/// on and the windows are mapped). Returns the GSI count covered.
pub fn init() -> u32 {
    let p = platform();
    let mut n = 0;
    let mut add = |base: usize, gsi_base: u32| {
        if n >= MAX_IOAPICS {
            return;
        }
        let _g = lock();
        let pins = encode::ioapic_pins(reg_read(base, encode::IOAPIC_REG_VER));
        for pin in 0..pins {
            let r = encode::ioapic_rte_reg(pin);
            reg_write(base, r, RTE_MASKED as u32);
            reg_write(base, r + 1, 0);
        }
        CHIPS[n].base.store(base, Ordering::Relaxed);
        CHIPS[n].gsi_base.store(gsi_base, Ordering::Relaxed);
        CHIPS[n].pins.store(pins, Ordering::Relaxed);
        n += 1;
    };
    match p.madt().filter(|m| m.n_ioapics != 0) {
        Some(m) => m.ioapics().iter().for_each(|io| add(io.addr as usize, io.gsi_base)),
        None => add(azos_limits::X86_IOAPIC_FALLBACK_BASE, 0),
    }
    N_CHIPS.store(n, Ordering::Release);
    (0..n).map(|i| CHIPS[i].pins.load(Ordering::Relaxed)).sum()
}

/// The chip and pin GSI `gsi` lands on.
fn locate(gsi: u32) -> Option<(usize, u32)> {
    let n = N_CHIPS.load(Ordering::Acquire);
    CHIPS[..n].iter().find_map(|c| {
        let b = c.gsi_base.load(Ordering::Relaxed);
        let pins = c.pins.load(Ordering::Relaxed);
        (gsi >= b && gsi < b + pins).then(|| (c.base.load(Ordering::Relaxed), gsi - b))
    })
}

/// Does some IOAPIC carry `gsi`?
pub fn has_gsi(gsi: u32) -> bool {
    locate(gsi).is_some()
}

/// The trigger a GSI takes when nobody says: the MADT override of the ISA
/// IRQ that lands on it; else virtio-mmio's (level, active-high: QEMU's
/// DSDT); else ISA's (edge, active-high) below 16 and PCI's (level,
/// active-low) above. Returns (level, active_low).
pub fn default_trigger(gsi: u32) -> (bool, bool) {
    let p = platform();
    if let Some(o) = p.madt().and_then(|m| m.isos().iter().copied().find(|o| o.gsi == gsi)) {
        let isa = o.bus == 0;
        return (o.level().unwrap_or(!isa), o.active_low().unwrap_or(!isa));
    }
    if p.virtio().iter().any(|d| d.gsi == gsi) {
        return (true, false);
    }
    if gsi < 16 { (false, false) } else { (true, true) }
}

/// Program GSI `gsi` to vector `IRQ_VECTOR_BASE + gsi` on APIC ID `dest`.
/// `false` if no IOAPIC has the GSI, the vector would reach the system
/// block, or the destination needs interrupt remapping.
pub fn route(gsi: u32, dest: u32, level: bool, active_low: bool, masked: bool) -> bool {
    let Some((base, pin)) = locate(gsi) else { return false };
    let Some(vector) = encode::gsi_vector(crate::apic::IRQ_VECTOR_BASE, gsi) else { return false };
    let Some(w) = encode::rte(vector, dest, level, active_low, masked) else { return false };
    let r = encode::ioapic_rte_reg(pin);
    let _g = lock();
    // Masked while the halves disagree, then the low word (mask last).
    reg_write(base, r, RTE_MASKED as u32);
    reg_write(base, r + 1, (w >> 32) as u32);
    reg_write(base, r, w as u32);
    true
}

/// Set or clear the mask bit of GSI `gsi`'s entry.
pub fn set_masked(gsi: u32, masked: bool) -> bool {
    let Some((base, pin)) = locate(gsi) else { return false };
    let r = encode::ioapic_rte_reg(pin);
    let _g = lock();
    let low = reg_read(base, r);
    let new = if masked { low | RTE_MASKED as u32 } else { low & !(RTE_MASKED as u32) };
    reg_write(base, r, new);
    true
}

/// Back to masked and unrouted.
pub fn release(gsi: u32) {
    if let Some((base, pin)) = locate(gsi) {
        let r = encode::ioapic_rte_reg(pin);
        let _g = lock();
        reg_write(base, r, RTE_MASKED as u32);
        reg_write(base, r + 1, 0);
    }
}

/// GSI `gsi`'s entry (for the boot log and tests).
pub fn entry(gsi: u32) -> Option<u64> {
    let (base, pin) = locate(gsi)?;
    let r = encode::ioapic_rte_reg(pin);
    let _g = lock();
    Some(reg_read(base, r) as u64 | (reg_read(base, r + 1) as u64) << 32)
}

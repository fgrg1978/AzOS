// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The local APIC, per CPU: x2APIC (MSRs 0x800+) when the CPU has it and
//! Kconfig `X86_X2APIC` allows it, else xAPIC MMIO at the MADT/IA32_APIC_BASE
//! address. One mode for the whole machine, chosen once by [`select_mode`]
//! on the boot CPU; every CPU then runs [`init_local`].
//!
//! The vector map is [`crate::encode`]'s; device lines go through
//! [`crate::ioapic`].

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::encode::{self, *};
use crate::hw;
use crate::platform_impl::{cpuid, platform};

/// The IOAPIC GSI block's first vector (Kconfig `X86_IRQ_VECTOR_BASE`).
pub const IRQ_VECTOR_BASE: u8 = azos_limits::X86_IRQ_VECTOR_BASE as u8;
const _: () = assert!(
    azos_limits::X86_IRQ_VECTOR_BASE >= 48 && azos_limits::X86_IRQ_VECTOR_BASE < SYSTEM_VECTOR_FLOOR as usize,
    "X86_IRQ_VECTOR_BASE must sit above the remapped 8259s (48) and below the system vectors (0xE0)"
);

static X2APIC: AtomicBool = AtomicBool::new(false);
/// The xAPIC register window (identity-mapped by `kernel_mmio_windows`).
static XAPIC_BASE: AtomicUsize = AtomicUsize::new(0);

/// Choose x2APIC or xAPIC for every CPU (boot CPU, before [`init_local`]).
/// Returns true for x2APIC.
pub fn select_mode() -> bool {
    let present = cpuid(1, 0).2 & (1 << 21) != 0;
    let x2 = azos_arch_api::isa::x86_64::X2APIC.gate(present);
    X2APIC.store(x2, Ordering::Relaxed);
    XAPIC_BASE.store(platform().lapic_pa as usize, Ordering::Relaxed);
    x2
}

/// The mode [`select_mode`] chose.
#[inline]
pub fn x2apic() -> bool {
    X2APIC.load(Ordering::Relaxed)
}

/// The xAPIC MMIO window (`None` in x2APIC mode): one page.
pub fn mmio_window() -> Option<usize> {
    if x2apic() { None } else { Some(XAPIC_BASE.load(Ordering::Relaxed)) }
}

#[inline]
pub fn read(reg: u32) -> u32 {
    if x2apic() {
        hw::rdmsr(x2apic_msr(reg)) as u32
    } else {
        let a = XAPIC_BASE.load(Ordering::Relaxed) + reg as usize;
        // SAFETY: an xAPIC register in the mapped LAPIC page.
        unsafe { core::ptr::read_volatile(a as *const u32) }
    }
}

#[inline]
pub fn write(reg: u32, v: u32) {
    if x2apic() {
        hw::wrmsr(x2apic_msr(reg), v as u64);
    } else {
        let a = XAPIC_BASE.load(Ordering::Relaxed) + reg as usize;
        // SAFETY: an xAPIC register in the mapped LAPIC page.
        unsafe { core::ptr::write_volatile(a as *mut u32, v) };
    }
}

/// This CPU's APIC ID (32-bit in x2APIC mode, 8-bit in xAPIC mode).
pub fn id() -> u32 {
    if x2apic() { read(LAPIC_ID) } else { read(LAPIC_ID) >> 24 }
}

/// Enable this CPU's LAPIC in the chosen mode: spurious vector, TPR 0, the
/// LINT pins (LINT0 masked: the 8259s are not wired through; the MADT's NMI
/// entries for this CPU on their pin), the error vector, the timer masked
/// until `timer::init_local`. `cpu` is the dense CPU number.
pub fn init_local(cpu: usize) {
    let base = hw::rdmsr(APIC_BASE_MSR);
    // xAPIC first, then x2APIC: the disabled -> x2APIC transition is invalid.
    hw::wrmsr(APIC_BASE_MSR, base | APIC_BASE_EN);
    if x2apic() {
        hw::wrmsr(APIC_BASE_MSR, base | APIC_BASE_EN | APIC_BASE_EXTD);
    }
    write(LAPIC_TPR, 0);
    write(LAPIC_LVT_TIMER, lvt_timer(TIMER_VECTOR, TimerMode::OneShot, true));
    let mut lint = [LVT_MASKED; 2];
    let uid = platform().madt().and_then(|m| m.cpus().get(cpu)).map(|c| c.uid);
    if let Some(m) = platform().madt() {
        for n in m.nmis() {
            if n.uid == u32::MAX || n.uid == 0xFF || Some(n.uid) == uid {
                if let Some(slot) = lint.get_mut(n.lint as usize) {
                    // NMI is edge by definition; polarity from MPS INTI flags.
                    *slot = LVT_DM_NMI | if n.flags & 0b11 == 0b11 { LVT_ACTIVE_LOW } else { 0 };
                }
            }
        }
    }
    write(LAPIC_LVT_LINT0, lint[0]);
    write(LAPIC_LVT_LINT1, lint[1]);
    write(LAPIC_LVT_ERROR, ERROR_VECTOR as u32);
    // ESR is write-then-read; two writes clear a stale error.
    write(LAPIC_ESR, 0);
    write(LAPIC_ESR, 0);
    write(LAPIC_SVR, svr(SPURIOUS_VECTOR));
    eoi();
}

/// End of interrupt for the vector in service (never for the spurious one).
#[inline(always)]
pub fn eoi() {
    write(LAPIC_EOI, 0);
}

/// Send the ICR low word `low` to APIC ID `dest`. `false` if the destination
/// is unreachable in this mode (above 255 in xAPIC mode).
pub fn send_raw(dest: u32, low: u32) -> bool {
    if x2apic() {
        // x2APIC ICR writes are not serializing: order earlier stores (the
        // enqueue an IPI announces) before the IPI, as Linux's
        // weak_wrmsr_fence does.
        // SAFETY: fences only.
        unsafe { core::arch::asm!("mfence", "lfence", options(nostack, preserves_flags)) };
        hw::wrmsr(x2apic_msr(LAPIC_ICR_LOW), icr_x2apic(dest, low));
        return true;
    }
    let Some(high) = icr_xapic_high(dest) else { return false };
    // Two registers: no interrupt (and no IPI from its handler) in between.
    let f = hw::rflags();
    hw::cli();
    wait_icr_idle();
    write(LAPIC_ICR_HIGH, high);
    write(LAPIC_ICR_LOW, low);
    wait_icr_idle();
    if f & hw::RFLAGS_IF != 0 {
        hw::sti();
    }
    true
}

fn wait_icr_idle() {
    while read(LAPIC_ICR_LOW) & ICR_DELIVERY_PENDING != 0 {
        core::hint::spin_loop();
    }
}

/// A fixed-vector IPI to dense CPU `cpu`.
pub fn send_ipi(cpu: usize, vector: u8) -> bool {
    match platform().apic_id(cpu) {
        Some(dest) => send_raw(dest, icr_fixed(vector)),
        None => false,
    }
}

/// A fixed-vector IPI to every CPU but this one (the shootdown broadcast).
pub fn send_ipi_all_but_self(vector: u8) {
    send_raw(0, icr_fixed(vector) | ICR_ALL_BUT_SELF);
}

/// The MSI address/data that deliver `vector` to dense CPU `cpu`.
pub fn msi(cpu: usize, vector: u8) -> Option<(u64, u32)> {
    let dest = platform().apic_id(cpu)?;
    Some((encode::msi_address(dest)?, encode::msi_data(vector)))
}

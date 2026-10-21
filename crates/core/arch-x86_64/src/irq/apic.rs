// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The local APIC, per CPU: x2APIC (MSRs 0x800+) when the CPU has it and
//! Kconfig `X86_X2APIC` allows it, else xAPIC MMIO at the MADT/IA32_APIC_BASE
//! address. One mode for the whole machine, chosen once by [`select_mode`]
//! on the boot CPU; every CPU then runs [`init_local`].
//!
//! The vector map is [`super::encode`]'s; device lines go through
//! [`super::ioapic`].

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use super::encode::{self, *};
use crate::cpu;
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

/// Choose x2APIC or xAPIC for every CPU (boot CPU, before [`init_local`]), by
/// [`encode::apic_mode`]: Kconfig `X86_X2APIC`, the CPU's CPUID bit, the
/// largest APIC ID in the MADT and the DMAR's X2APIC_OPT_OUT. Returns true
/// for x2APIC and the reason.
pub fn select_mode() -> (bool, encode::ApicWhy) {
    use azos_arch_api::isa::{x86_64::X2APIC as policy, ExtPolicy};
    let p = platform();
    let present = cpuid(1, 0).2 & (1 << 21) != 0;
    let max_id = p.apic_ids[..p.n_cpus].iter().copied().max().unwrap_or(0);
    let opt_out = p.acpi.dmar.is_some_and(|d| d.flags & 0b10 != 0);
    let (x2, why) = encode::apic_mode(!policy.allowed(), policy == ExtPolicy::Require, present, opt_out, max_id);
    X2APIC.store(x2, Ordering::Relaxed);
    XAPIC_BASE.store(p.lapic_pa as usize, Ordering::Relaxed);
    (x2, why)
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
        cpu::rdmsr(x2apic_msr(reg)) as u32
    } else {
        let a = XAPIC_BASE.load(Ordering::Relaxed) + reg as usize;
        // SAFETY: an xAPIC register in the mapped LAPIC page.
        unsafe { core::ptr::read_volatile(a as *const u32) }
    }
}

#[inline]
pub fn write(reg: u32, v: u32) {
    if x2apic() {
        cpu::wrmsr(x2apic_msr(reg), v as u64);
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
    let base = cpu::rdmsr(APIC_BASE_MSR);
    if x2apic() {
        // xAPIC first, then x2APIC: the disabled -> x2APIC transition is
        // invalid.
        if base & APIC_BASE_EXTD == 0 {
            cpu::wrmsr(APIC_BASE_MSR, base | APIC_BASE_EN);
        }
        cpu::wrmsr(APIC_BASE_MSR, base | APIC_BASE_EN | APIC_BASE_EXTD);
    } else if base & APIC_BASE_EXTD != 0 {
        // Firmware left x2APIC on and Kconfig says n: x2APIC -> xAPIC must
        // pass through disabled (SDM 11.12.5).
        cpu::wrmsr(APIC_BASE_MSR, base & !(APIC_BASE_EN | APIC_BASE_EXTD));
        cpu::wrmsr(APIC_BASE_MSR, (base & !APIC_BASE_EXTD) | APIC_BASE_EN);
    } else {
        cpu::wrmsr(APIC_BASE_MSR, base | APIC_BASE_EN);
    }
    // Software-enable first: while SVR[8] is clear every LVT stays masked
    // and writes that unmask one are ignored (SDM 11.4.7.2).
    write(LAPIC_SVR, svr(SPURIOUS_VECTOR));
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
        cpu::wrmsr(x2apic_msr(LAPIC_ICR_LOW), icr_x2apic(dest, low));
        return true;
    }
    let Some(high) = icr_xapic_high(dest) else { return false };
    // Two registers: no interrupt (and no IPI from its handler) in between.
    let f = cpu::rflags();
    cpu::cli();
    wait_icr_idle();
    write(LAPIC_ICR_HIGH, high);
    write(LAPIC_ICR_LOW, low);
    wait_icr_idle();
    if f & cpu::RFLAGS_IF != 0 {
        cpu::sti();
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

// ── MSI vectors ─────────────────────────────────────────────────────────────
//
// PCI MSI and MSI-X deliver straight to a LAPIC, with no IOAPIC line: the
// device writes `msi(cpu, vector)`'s address/data pair. The vectors come from
// a block just above the IOAPIC lines (`encode::msi_block`), so `dispatch`
// tells an MSI from a GSI by number alone.

/// Most MSI vectors handed out (Kconfig `X86_MSI_VECTORS`).
const MSI_MAX: usize = azos_limits::X86_MSI_VECTORS;
const _: () = assert!(MSI_MAX >= 1 && MSI_MAX <= 128, "X86_MSI_VECTORS is 1..=128");

/// The block's first vector and size, fixed by the first [`msi_alloc`]
/// (0 until then: no MSI vector is owned).
static MSI_FIRST: AtomicU8 = AtomicU8::new(0);
static MSI_ROOM: AtomicU8 = AtomicU8::new(0);
/// Vectors handed out so far.
static MSI_USED: AtomicU8 = AtomicU8::new(0);
/// Deliveries per MSI vector (index = vector - first).
static MSI_HITS: [AtomicU32; MSI_MAX] = [const { AtomicU32::new(0) }; MSI_MAX];

/// Reserve `n` consecutive MSI vectors; the first one. `None` once the block
/// is spent, or before the IOAPICs are registered (the block sits above them).
/// Boot CPU, during device bring-up.
pub fn msi_alloc(n: u8) -> Option<u8> {
    if MSI_FIRST.load(Ordering::Acquire) == 0 {
        let limit = super::ioapic::gsi_limit();
        if limit == 0 {
            return None;
        }
        let (first, room) = encode::msi_block(IRQ_VECTOR_BASE, limit, MSI_MAX as u8);
        MSI_ROOM.store(room, Ordering::Relaxed);
        MSI_FIRST.store(first, Ordering::Release);
    }
    let first = MSI_FIRST.load(Ordering::Acquire);
    let room = MSI_ROOM.load(Ordering::Relaxed);
    MSI_USED
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
            (n as u16 + used as u16 <= room as u16).then_some(used + n)
        })
        .ok()
        .map(|used| first + used)
}

/// Vectors of the block given back ([`msi_free`]), one bit per vector of the
/// block (`vector - first`), for [`msi_alloc_one`] to hand out again.
static MSI_FREED: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// One MSI vector for a ring-3 handler (`DEVICE_IRQ_BIND` on an MSI line): a
/// vector given back by [`msi_free`] first, else a new one ([`msi_alloc`]).
/// Unlike the kernel's, it is returned when the binding goes, so a driver that
/// restarts does not spend the block. `None` once the block is spent.
pub fn msi_alloc_one() -> Option<u8> {
    let first = MSI_FIRST.load(Ordering::Acquire);
    if first != 0 {
        for (w, freed) in MSI_FREED.iter().enumerate() {
            let mut cur = freed.load(Ordering::Acquire);
            while cur != 0 {
                let bit = cur.trailing_zeros();
                match freed.compare_exchange(cur, cur & !(1u64 << bit), Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => return Some(first + (w as u32 * 64 + bit) as u8),
                    Err(now) => cur = now,
                }
            }
        }
    }
    msi_alloc(1)
}

/// Give back a vector [`msi_alloc_one`] handed out. A vector outside the
/// block is ignored.
pub fn msi_free(vector: u8) {
    let first = MSI_FIRST.load(Ordering::Acquire);
    let i = vector.wrapping_sub(first) as usize;
    if first != 0 && vector >= first && i < MSI_MAX {
        MSI_FREED[i / 64].fetch_or(1u64 << (i % 64), Ordering::AcqRel);
    }
}

/// Does `vector` belong to a reserved MSI vector?
#[inline]
pub fn msi_owns(vector: u8) -> bool {
    let first = MSI_FIRST.load(Ordering::Acquire);
    first != 0 && vector >= first && (vector - first) < MSI_USED.load(Ordering::Acquire)
}

/// Count a delivery on `vector` (the interrupt path, before its handler).
#[inline]
pub fn msi_note(vector: u8) {
    let first = MSI_FIRST.load(Ordering::Acquire);
    if let Some(h) = MSI_HITS.get(vector.wrapping_sub(first) as usize) {
        h.fetch_add(1, Ordering::Relaxed);
    }
}

/// Deliveries counted on `vector`.
pub fn msi_delivered(vector: u8) -> u32 {
    let first = MSI_FIRST.load(Ordering::Acquire);
    MSI_HITS.get(vector.wrapping_sub(first) as usize).map_or(0, |h| h.load(Ordering::Relaxed))
}

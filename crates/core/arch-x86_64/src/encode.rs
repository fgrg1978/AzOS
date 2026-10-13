// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The pure half of the x86 interrupt and clock hardware: register words
//! (LAPIC ICR/LVT/TDCR, IOAPIC redirection entries, MSI address/data) and
//! the fixed-point clock conversions. No instruction runs here, so the host
//! tests pull this file in with `#[path]` (`tests/host/x86-platform-tests`):
//! a wrong bit here routes an interrupt to the wrong CPU or arms a timer for
//! the wrong instant, and nothing faults.

// ── The IDT vector map ───────────────────────────────────────────────────
//
//   0..31     CPU exceptions
//   32..47    the 8259s, remapped there and masked (a spurious IRQ 7/15
//             lands here, never on an exception)
//   base..    IOAPIC GSIs: vector = base + GSI (Kconfig X86_IRQ_VECTOR_BASE)
//   0xE0..    system vectors, highest priority class: timer, IPIs, error,
//             spurious
// The trap path (vector >= 32) hands every one of these to the platform's
// interrupt dispatch; `TrapContext::irq_number` is `vector - base`.

/// The 8259s' remapped vectors.
pub const PIC_VECTOR_BASE: u8 = 0x20;
/// The lowest vector of the system block; a GSI vector stays below it.
pub const SYSTEM_VECTOR_FLOOR: u8 = 0xE0;
/// The LAPIC timer (one-shot or TSC-deadline).
pub const TIMER_VECTOR: u8 = 0xEF;
/// The function-call IPI (run a queued callback, e.g. an icache sync).
pub const CALL_VECTOR: u8 = 0xFB;
/// The TLB-shootdown IPI.
pub const TLB_VECTOR: u8 = 0xFC;
/// The reschedule IPI (`Interrupts::send_ipi`).
pub const RESCHED_VECTOR: u8 = 0xFD;
/// The LAPIC error interrupt.
pub const ERROR_VECTOR: u8 = 0xFE;
/// The LAPIC spurious vector (low nibble all ones for pre-P6 parts); never
/// acknowledged with an EOI.
pub const SPURIOUS_VECTOR: u8 = 0xFF;

/// The vector GSI `gsi` is routed to with the GSI block at `base`; `None`
/// if it would reach the system block.
pub const fn gsi_vector(base: u8, gsi: u32) -> Option<u8> {
    let v = base as u32 + gsi;
    if v >= SYSTEM_VECTOR_FLOOR as u32 { None } else { Some(v as u8) }
}

/// The GSI a device vector carries (the inverse of [`gsi_vector`]).
pub const fn vector_gsi(base: u8, vector: u8) -> Option<u32> {
    if vector < base || vector >= SYSTEM_VECTOR_FLOOR {
        None
    } else {
        Some((vector - base) as u32)
    }
}

/// The MSI block: up to `max` vectors from just above the IOAPIC lines
/// (`base + gsi_limit`) to the system block, as `(first, count)`. Fewer than
/// `max` (down to none) when the lines leave less room.
pub const fn msi_block(base: u8, gsi_limit: u32, max: u8) -> (u8, u8) {
    let first = base as u32 + gsi_limit;
    if first >= SYSTEM_VECTOR_FLOOR as u32 {
        return (SYSTEM_VECTOR_FLOOR, 0);
    }
    let room = SYSTEM_VECTOR_FLOOR as u32 - first;
    (first as u8, if room < max as u32 { room as u8 } else { max })
}

// ── LAPIC registers (xAPIC MMIO offset; x2APIC MSR = 0x800 + offset >> 4) ──

pub const LAPIC_ID: u32 = 0x020;
pub const LAPIC_VERSION: u32 = 0x030;
pub const LAPIC_TPR: u32 = 0x080;
pub const LAPIC_EOI: u32 = 0x0B0;
pub const LAPIC_SVR: u32 = 0x0F0;
pub const LAPIC_ESR: u32 = 0x280;
pub const LAPIC_ICR_LOW: u32 = 0x300;
pub const LAPIC_ICR_HIGH: u32 = 0x310;
pub const LAPIC_LVT_TIMER: u32 = 0x320;
pub const LAPIC_LVT_LINT0: u32 = 0x350;
pub const LAPIC_LVT_LINT1: u32 = 0x360;
pub const LAPIC_LVT_ERROR: u32 = 0x370;
pub const LAPIC_TIMER_INIT: u32 = 0x380;
pub const LAPIC_TIMER_CURRENT: u32 = 0x390;
pub const LAPIC_TIMER_DIVIDE: u32 = 0x3E0;

/// The x2APIC MSR of an xAPIC register offset (SDM Vol. 3 Table 11-6).
pub const fn x2apic_msr(reg: u32) -> u32 {
    0x800 + (reg >> 4)
}

/// IA32_APIC_BASE (MSR 0x1B): global enable, x2APIC enable, the base.
pub const APIC_BASE_MSR: u32 = 0x1B;
pub const APIC_BASE_BSP: u64 = 1 << 8;
pub const APIC_BASE_EXTD: u64 = 1 << 10;
pub const APIC_BASE_EN: u64 = 1 << 11;
pub const APIC_BASE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// SVR: APIC software enable plus the spurious vector.
pub const fn svr(spurious_vector: u8) -> u32 {
    (1 << 8) | spurious_vector as u32
}

/// LVT mask bit (every LVT entry).
pub const LVT_MASKED: u32 = 1 << 16;
/// LVT delivery mode NMI (LINT entries).
pub const LVT_DM_NMI: u32 = 0b100 << 8;
/// LVT level-triggered (LINT entries; NMI must be edge).
pub const LVT_LEVEL: u32 = 1 << 15;
/// LVT input polarity active-low (LINT entries).
pub const LVT_ACTIVE_LOW: u32 = 1 << 13;

/// LVT timer mode (bits 17-18).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimerMode {
    OneShot,
    Periodic,
    TscDeadline,
}

/// The LVT timer word.
pub const fn lvt_timer(vector: u8, mode: TimerMode, masked: bool) -> u32 {
    let m = match mode {
        TimerMode::OneShot => 0,
        TimerMode::Periodic => 1 << 17,
        TimerMode::TscDeadline => 2 << 17,
    };
    vector as u32 | m | if masked { LVT_MASKED } else { 0 }
}

/// The divide-configuration register's encoding of `divide` (1..=128, a
/// power of two): bits 0,1,3 (SDM Figure 11-10). `None` for anything else.
pub const fn tdcr(divide: u32) -> Option<u32> {
    Some(match divide {
        1 => 0b1011,
        2 => 0b0000,
        4 => 0b0001,
        8 => 0b0010,
        16 => 0b0011,
        32 => 0b1000,
        64 => 0b1001,
        128 => 0b1010,
        _ => return None,
    })
}

// ── ICR (interrupt command register) ─────────────────────────────────────

/// Delivery modes (bits 8-10).
pub const ICR_DM_FIXED: u32 = 0b000 << 8;
pub const ICR_DM_NMI: u32 = 0b100 << 8;
pub const ICR_DM_INIT: u32 = 0b101 << 8;
pub const ICR_DM_STARTUP: u32 = 0b110 << 8;
/// xAPIC only: delivery status (send pending).
pub const ICR_DELIVERY_PENDING: u32 = 1 << 12;
/// Level assert (bit 14); INIT must be sent asserted.
pub const ICR_ASSERT: u32 = 1 << 14;
/// Level-triggered (bit 15): the INIT de-assert IPI only.
pub const ICR_LEVEL: u32 = 1 << 15;
/// Destination shorthand "all excluding self" (bits 18-19 = 11).
pub const ICR_ALL_BUT_SELF: u32 = 0b11 << 18;

/// A fixed-vector IPI's low word.
pub const fn icr_fixed(vector: u8) -> u32 {
    ICR_DM_FIXED | ICR_ASSERT | vector as u32
}

/// INIT (asserted, level).
pub const fn icr_init() -> u32 {
    ICR_DM_INIT | ICR_ASSERT | ICR_LEVEL
}

/// INIT level de-assert (needed by pre-Pentium 4 CPUs, harmless after).
pub const fn icr_init_deassert() -> u32 {
    ICR_DM_INIT | ICR_LEVEL
}

/// STARTUP: the AP starts in real mode at `page << 12` (CS = page << 8, IP 0).
/// `None` when `page_pa` is not a page below 1 MiB.
pub const fn icr_sipi(page_pa: u64) -> Option<u32> {
    if page_pa & 0xFFF != 0 || page_pa >= 0x10_0000 {
        return None;
    }
    Some(ICR_DM_STARTUP | ICR_ASSERT | (page_pa >> 12) as u32)
}

/// The 64-bit x2APIC ICR (MSR 0x830): destination APIC ID in bits 32-63.
pub const fn icr_x2apic(dest: u32, low: u32) -> u64 {
    ((dest as u64) << 32) | low as u64
}

/// The xAPIC ICR high word: an 8-bit physical destination in bits 24-31.
/// `None` above 255 (that CPU is reachable only in x2APIC mode).
pub const fn icr_xapic_high(dest: u32) -> Option<u32> {
    if dest > 0xFF {
        return None;
    }
    Some(dest << 24)
}

// ── IOAPIC ───────────────────────────────────────────────────────────────

/// IOAPIC indirect registers: IOREGSEL at +0, IOWIN at +0x10.
pub const IOAPIC_REGSEL: usize = 0x00;
pub const IOAPIC_WIN: usize = 0x10;
pub const IOAPIC_REG_ID: u32 = 0x00;
pub const IOAPIC_REG_VER: u32 = 0x01;
/// Redirection entry `pin`: low word at 0x10 + 2*pin, high at + 1.
pub const fn ioapic_rte_reg(pin: u32) -> u32 {
    0x10 + 2 * pin
}

/// Pins on an IOAPIC from its version register (max redirection entry + 1).
pub const fn ioapic_pins(ver: u32) -> u32 {
    ((ver >> 16) & 0xFF) + 1
}

pub const RTE_MASKED: u64 = 1 << 16;
pub const RTE_LEVEL: u64 = 1 << 15;
pub const RTE_ACTIVE_LOW: u64 = 1 << 13;

/// A fixed-delivery, physical-destination redirection entry. `None` for a
/// destination above 255: an IOAPIC carries an 8-bit APIC ID, so such a CPU
/// needs interrupt remapping (not implemented).
pub const fn rte(vector: u8, dest_apic: u32, level: bool, active_low: bool, masked: bool) -> Option<u64> {
    if dest_apic > 0xFF {
        return None;
    }
    let mut w = vector as u64;
    if level {
        w |= RTE_LEVEL;
    }
    if active_low {
        w |= RTE_ACTIVE_LOW;
    }
    if masked {
        w |= RTE_MASKED;
    }
    Some(w | ((dest_apic as u64) << 56))
}

// ── MSI ──────────────────────────────────────────────────────────────────

/// MSI address: the LAPIC window with the destination APIC ID in bits
/// 12-19 (physical mode, no redirection hint). `None` above 255.
pub const fn msi_address(dest_apic: u32) -> Option<u64> {
    if dest_apic > 0xFF {
        return None;
    }
    Some(0xFEE0_0000 | ((dest_apic as u64) << 12))
}

/// MSI data: fixed delivery, edge, the vector.
pub const fn msi_data(vector: u8) -> u32 {
    vector as u32
}

// ── PCI configuration mechanism #1 ───────────────────────────────────────

/// The value written to port 0xCF8 to select dword `offset & 0xFC` of
/// function `(bus, device, function)`: enable bit, bus, device (5 bits),
/// function (3 bits), register.
pub const fn pci_port_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    0x8000_0000 | ((bus as u32) << 16) | (((device & 0x1F) as u32) << 11)
        | (((function & 0x07) as u32) << 8) | (offset & 0xFC) as u32
}

// ── 8259 PIC ─────────────────────────────────────────────────────────────

/// The ICW sequence that remaps both 8259s to `base..base+16` (master then
/// slave), cascade on IRQ 2, 8086 mode: (port, value) in order. Masking
/// them afterwards (OCW1 = 0xFF to 0x21 and 0xA1) is the caller's.
pub const fn pic_remap(base: u8) -> [(u16, u8); 8] {
    [
        (0x20, 0x11), (0xA0, 0x11),
        (0x21, base), (0xA1, base + 8),
        (0x21, 0x04), (0xA1, 0x02),
        (0x21, 0x01), (0xA1, 0x01),
    ]
}

// ── Clock math ───────────────────────────────────────────────────────────

/// A rate conversion `out = in * mult >> 32` (Linux's clocksource
/// mult/shift with the shift fixed at 32): one 64x64->128 `mul` per call.
/// Exact to 2^-32 relative; `mult` fits 64 bits for any ratio below 2^32.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Scale {
    pub mult: u64,
}

impl Scale {
    /// 1:1.
    pub const IDENTITY: Scale = Scale { mult: 1 << 32 };

    /// The conversion from a `from_hz` counter to `to_hz` ticks. `None` for a
    /// zero rate or a ratio of 2^32 or more.
    pub const fn new(from_hz: u64, to_hz: u64) -> Option<Scale> {
        if from_hz == 0 || to_hz == 0 {
            return None;
        }
        let m = ((to_hz as u128) << 32) / from_hz as u128;
        if m == 0 || m > u64::MAX as u128 {
            return None;
        }
        Some(Scale { mult: m as u64 })
    }

    /// `x` converted, rounded down, saturating at `u64::MAX`.
    #[inline(always)]
    pub const fn apply(self, x: u64) -> u64 {
        let p = (x as u128 * self.mult as u128) >> 32;
        if p > u64::MAX as u128 { u64::MAX } else { p as u64 }
    }

    /// `x` converted, rounded up: a deadline converted this way is never
    /// earlier than the one asked for.
    #[inline(always)]
    pub const fn apply_ceil(self, x: u64) -> u64 {
        let p = (x as u128 * self.mult as u128 + 0xFFFF_FFFF) >> 32;
        if p > u64::MAX as u128 { u64::MAX } else { p as u64 }
    }
}

/// How the clock's TSC rate may be found (Kconfig `X86_INVARIANT_TSC`
/// against CPUID.80000007H:EDX[8]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClockPlan {
    /// Invariant TSC: its rate is a constant, so a rate CPUID or the
    /// hypervisor states (leaf 15H, 0x40000010) is as good as a measured one.
    Stated,
    /// `n`, or no invariance: the TSC's rate can follow the P/C-state, so a
    /// stated or nominal rate (leaf 15H, hypervisor) is not taken while a
    /// measurement (HPET, PIT) can be; leaf 16H only when both fail.
    Measured,
    /// `require` and the TSC is not invariant: the boot refuses (the `[ISA]`
    /// line); the clock is still calibrated measured so the boot line prints.
    Refused,
}

impl ClockPlan {
    /// The boot line's words.
    pub const fn label(self) -> &'static str {
        match self {
            ClockPlan::Stated => "invariant TSC",
            ClockPlan::Measured => "TSC rate measured, not stated",
            ClockPlan::Refused => "TSC not invariant, REFUSED",
        }
    }
}

/// The clocksource decision, from the Kconfig choice (`allowed` = not `n`,
/// `required`) and the CPU's invariant-TSC bit.
pub const fn clock_plan(allowed: bool, required: bool, invariant: bool) -> ClockPlan {
    if required && !invariant {
        ClockPlan::Refused
    } else if allowed && invariant {
        ClockPlan::Stated
    } else {
        ClockPlan::Measured
    }
}

/// The TSC rate from CPUID leaf 0x15 (EAX denominator, EBX numerator, ECX
/// crystal Hz): exact when all three are reported, `None` otherwise.
pub const fn tsc_hz_from_leaf15(eax: u32, ebx: u32, ecx: u32) -> Option<u64> {
    if eax == 0 || ebx == 0 || ecx == 0 {
        return None;
    }
    Some(ecx as u64 * ebx as u64 / eax as u64)
}

/// The processor base frequency from CPUID leaf 0x16 (EAX, MHz): nominal,
/// not measured, so only a fallback.
pub const fn tsc_hz_from_leaf16(eax: u32) -> Option<u64> {
    let mhz = eax & 0xFFFF;
    if mhz == 0 { None } else { Some(mhz as u64 * 1_000_000) }
}

/// The hypervisor timing leaf 0x40000010 (EAX: TSC kHz), as VMware, KVM
/// (`vmware-cpuid-freq`) and others report it.
pub const fn tsc_hz_from_hv_leaf(eax: u32) -> Option<u64> {
    if eax == 0 { None } else { Some(eax as u64 * 1_000) }
}

/// The 8254 PIT input clock.
pub const PIT_HZ: u64 = 1_193_182;

/// The PIT counts in a `ms` window: `None` past the 16-bit counter
/// (54 ms) or for 0.
pub const fn pit_count_for_ms(ms: u32) -> Option<u16> {
    let c = PIT_HZ * ms as u64 / 1000;
    if c == 0 || c > 0xFFFF { None } else { Some(c as u16) }
}

/// Why the LAPIC runs in the mode [`apic_mode`] chose.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ApicWhy {
    /// x2APIC: the CPU has it and nothing argues against it.
    Preferred,
    /// x2APIC: Kconfig `X86_X2APIC` = require.
    Required,
    /// x2APIC although the firmware asked for xAPIC: an APIC ID above 254 is
    /// out of an xAPIC's reach.
    IdsNeedIt,
    /// xAPIC: the CPU has no x2APIC.
    NotPresent,
    /// xAPIC: Kconfig `X86_X2APIC` = n.
    PolicyNever,
    /// xAPIC: the DMAR asks the OS not to enable x2APIC
    /// (X2APIC_OPT_OUT, set when the platform has no interrupt remapping to
    /// make it safe) and every APIC ID fits.
    FirmwareOptOut,
}

impl ApicWhy {
    pub const fn label(self) -> &'static str {
        match self {
            ApicWhy::Preferred => "the CPU has it",
            ApicWhy::Required => "X86_X2APIC=require",
            ApicWhy::IdsNeedIt => "an APIC ID above 254 needs it",
            ApicWhy::NotPresent => "the CPU has no x2APIC",
            ApicWhy::PolicyNever => "X86_X2APIC=n",
            ApicWhy::FirmwareOptOut => "the DMAR asks for xAPIC (X2APIC_OPT_OUT)",
        }
    }
}

/// x2APIC or xAPIC for the whole machine, in this order: `n` (never) and no
/// CPU support give xAPIC; `require` gives x2APIC (the boot refuses a CPU
/// without it); an APIC ID above 254, which an xAPIC cannot address, gives
/// x2APIC over the firmware's opt-out; the DMAR's X2APIC_OPT_OUT gives
/// xAPIC; else x2APIC. `max_apic_id` is the largest ID the MADT lists.
pub const fn apic_mode(never: bool, require: bool, cpu_x2apic: bool, dmar_opt_out: bool, max_apic_id: u32)
    -> (bool, ApicWhy)
{
    if never {
        return (false, ApicWhy::PolicyNever);
    }
    if !cpu_x2apic {
        return (false, ApicWhy::NotPresent);
    }
    if require {
        return (true, ApicWhy::Required);
    }
    if max_apic_id > 254 {
        return (true, ApicWhy::IdsNeedIt);
    }
    if dmar_opt_out {
        return (false, ApicWhy::FirmwareOptOut);
    }
    (true, ApicWhy::Preferred)
}

/// The ACPI PM timer's rate (ACPI 6.x §4.8.3.3): 3.579545 MHz.
pub const PMTMR_HZ: u64 = 3_579_545;

/// The PM timer counter's valid bits: 32 with the FADT's TMR_VAL_EXT, else 24.
pub const fn pmtmr_mask(wide: bool) -> u32 {
    if wide { 0xFFFF_FFFF } else { 0x00FF_FFFF }
}

/// Ticks between two reads of the counter, across at most one wrap.
pub const fn pmtmr_elapsed(c0: u32, c1: u32, wide: bool) -> u32 {
    c1.wrapping_sub(c0) & pmtmr_mask(wide)
}

/// The PM timer ticks in a `ms` window: `None` for 0 or a window that could
/// pass a whole wrap of the 24-bit counter unseen (4.69 s; half of it is the
/// bound).
pub const fn pmtmr_ticks_for_ms(ms: u32) -> Option<u32> {
    let c = PMTMR_HZ * ms as u64 / 1000;
    if c == 0 || c > (pmtmr_mask(false) / 2) as u64 { None } else { Some(c as u32) }
}

/// A counter's rate from a calibration window: `ref_ticks` of a `ref_hz`
/// reference elapsed while the counter advanced `delta`.
pub const fn rate_from_window(delta: u64, ref_ticks: u64, ref_hz: u64) -> Option<u64> {
    if ref_ticks == 0 {
        return None;
    }
    let r = delta as u128 * ref_hz as u128 / ref_ticks as u128;
    if r == 0 || r > u64::MAX as u128 { None } else { Some(r as u64) }
}

/// The HPET main counter's rate from its period (femtoseconds, the top half
/// of GCAP_ID). The spec bounds the period at 100 ns (0x05F5E100 fs).
pub const fn hpet_hz(period_fs: u32) -> Option<u64> {
    if period_fs == 0 || period_fs > 0x05F5_E100 {
        return None;
    }
    Some(1_000_000_000_000_000 / period_fs as u64)
}

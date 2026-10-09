// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The clock and the per-CPU timer.
//!
//! **The clock** (`Cpu::now_ticks`) counts at Kconfig `TIMER_FREQ`, the
//! rate every `N * TIMER_FREQ` timeout in the tree is written in, so it is
//! the TSC scaled: `ticks = base_ticks + (tsc - base_tsc) * mult >> 32`
//! (one `rdtsc`, one 64x64->128 `mul`). The TSC rate comes from
//! [`calibrate`] (boot CPU, `timer_probe`, before the PMM): CPUID 15H when
//! it is complete and Kconfig `X86_TSC_FREQ_CPUID` trusts it, else the
//! hypervisor timing leaf, else measured against the HPET (Kconfig
//! `X86_HPET`) or the PIT over `X86_TSC_CALIBRATE_MS`, else CPUID 16H's
//! nominal base frequency. Until then the scale is 1:1; the switch keeps
//! the clock continuous (`base_*`), and it happens once, single-threaded.
//!
//! **The timer** fires `TIMER_VECTOR` at a deadline in clock ticks: the
//! TSC-deadline MSR when the CPU has it and Kconfig `X86_TSC_DEADLINE`
//! allows it (the deadline converted back to TSC, rounded up), else the
//! LAPIC one-shot counter, its rate measured against the TSC by
//! [`calibrate_lapic`].

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use crate::encode::{self, Scale, TimerMode, TIMER_VECTOR};
use crate::hw;
use crate::platform_impl::{cpuid, platform};

/// The clock's rate (Kconfig `TIMER_FREQ`).
pub const TICK_HZ: u64 = azos_limits::TIMER_FREQ as u64;

static TSC_HZ: AtomicU64 = AtomicU64::new(0);
static TO_TICKS: AtomicU64 = AtomicU64::new(Scale::IDENTITY.mult);
static TO_TSC: AtomicU64 = AtomicU64::new(Scale::IDENTITY.mult);
static BASE_TSC: AtomicU64 = AtomicU64::new(0);
static BASE_TICKS: AtomicU64 = AtomicU64::new(0);
static SOURCE: AtomicU8 = AtomicU8::new(TscSource::Assumed as u8);
static DEADLINE_MODE: AtomicBool = AtomicBool::new(false);
static LAPIC_HZ: AtomicU64 = AtomicU64::new(0);
static TO_LAPIC: AtomicU64 = AtomicU64::new(0);

/// IA32_TSC_DEADLINE.
const TSC_DEADLINE_MSR: u32 = 0x6E0;

/// Where the TSC rate came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum TscSource {
    /// Nothing answered: the TSC is taken to run at TIMER_FREQ.
    Assumed = 0,
    Cpuid15 = 1,
    Hypervisor = 2,
    Hpet = 3,
    Pit = 4,
    Cpuid16 = 5,
}

impl TscSource {
    pub const fn name(self) -> &'static str {
        match self {
            TscSource::Assumed => "assumed (TIMER_FREQ)",
            TscSource::Cpuid15 => "CPUID 15H",
            TscSource::Hypervisor => "hypervisor leaf 0x40000010",
            TscSource::Hpet => "HPET",
            TscSource::Pit => "PIT channel 0",
            TscSource::Cpuid16 => "CPUID 16H (nominal)",
        }
    }
    fn from_u8(v: u8) -> Self {
        match v {
            1 => TscSource::Cpuid15,
            2 => TscSource::Hypervisor,
            3 => TscSource::Hpet,
            4 => TscSource::Pit,
            5 => TscSource::Cpuid16,
            _ => TscSource::Assumed,
        }
    }
}

/// The clock, in TIMER_FREQ ticks.
#[inline(always)]
pub fn now_ticks() -> u64 {
    let tsc = hw::rdtsc();
    let scale = Scale { mult: TO_TICKS.load(Ordering::Relaxed) };
    BASE_TICKS.load(Ordering::Relaxed)
        .wrapping_add(scale.apply(tsc.wrapping_sub(BASE_TSC.load(Ordering::Relaxed))))
}

/// The TSC value at clock tick `ticks` (rounded up; a past tick gives a
/// past TSC value).
#[inline(always)]
pub fn ticks_to_tsc(ticks: u64) -> u64 {
    let base_ticks = BASE_TICKS.load(Ordering::Relaxed);
    let base_tsc = BASE_TSC.load(Ordering::Relaxed);
    if ticks <= base_ticks {
        return base_tsc;
    }
    let scale = Scale { mult: TO_TSC.load(Ordering::Relaxed) };
    base_tsc.saturating_add(scale.apply_ceil(ticks - base_ticks))
}

/// The TSC rate in Hz (0 before [`calibrate`]).
pub fn tsc_hz() -> u64 {
    TSC_HZ.load(Ordering::Relaxed)
}

pub fn source() -> TscSource {
    TscSource::from_u8(SOURCE.load(Ordering::Relaxed))
}

/// The TSC value `us` microseconds from now (for spin delays before and
/// after calibration: an uncalibrated TSC is taken at TIMER_FREQ).
pub fn tsc_after_us(us: u64) -> u64 {
    let hz = match tsc_hz() { 0 => TICK_HZ, hz => hz };
    hw::rdtsc().saturating_add((us as u128 * hz as u128 / 1_000_000) as u64)
}

/// Spin `us` microseconds on the TSC.
pub fn udelay(us: u64) {
    let end = tsc_after_us(us);
    while hw::rdtsc() < end {
        core::hint::spin_loop();
    }
}

/// Is the TSC invariant (constant rate in every P/C-state)?
pub fn invariant_tsc() -> bool {
    cpuid(0x8000_0000, 0).0 >= 0x8000_0007 && cpuid(0x8000_0007, 0).3 & (1 << 8) != 0
}

fn rate_cpuid15() -> Option<u64> {
    if crate::platform_impl::cpuid_max() < 0x15 {
        return None;
    }
    let (a, b, c, _) = cpuid(0x15, 0);
    encode::tsc_hz_from_leaf15(a, b, c)
}

fn rate_cpuid16() -> Option<u64> {
    if crate::platform_impl::cpuid_max() < 0x16 {
        return None;
    }
    encode::tsc_hz_from_leaf16(cpuid(0x16, 0).0)
}

fn rate_hypervisor() -> Option<u64> {
    if cpuid(1, 0).2 & (1 << 31) == 0 || cpuid(0x4000_0000, 0).0 < 0x4000_0010 {
        return None;
    }
    encode::tsc_hz_from_hv_leaf(cpuid(0x4000_0010, 0).0)
}

/// Plausible TSC rates: anything outside is a broken reference.
const TSC_HZ_MIN: u64 = 1_000_000;
const TSC_HZ_MAX: u64 = 100_000_000_000;

/// The TSC against the PIT's channel 0, read through the latch command:
/// its gate is always on, unlike channel 2's, which hangs off port 0x61 and
/// a PC speaker QEMU microvm does not have. Mode 0 from 0xFFFF counts down
/// once; IRQ 0 stays masked (interrupts are off and the IOAPIC pin masked).
fn rate_pit(ms: u32) -> Option<u64> {
    let want = encode::pit_count_for_ms(ms)? as u64;
    let read = || {
        hw::outb(0x43, 0x00); // latch channel 0
        let lo = hw::inb(0x40) as u64;
        let hi = hw::inb(0x40) as u64;
        lo | hi << 8
    };
    hw::outb(0x43, 0x30); // channel 0, lobyte/hibyte, mode 0, binary
    hw::outb(0x40, 0xFF);
    hw::outb(0x40, 0xFF);
    let c0 = read();
    let t0 = hw::rdtsc();
    // A missing PIT reads 0xFFFF forever: bounded, then the range check.
    let mut spins: u64 = 0;
    let elapsed = loop {
        let d = c0.saturating_sub(read());
        if d >= want {
            break d;
        }
        spins += 1;
        // A 54 ms window takes a few thousand latch reads even at one VM
        // exit each; a million means no PIT.
        if spins > 1 << 20 {
            return None;
        }
    };
    let t1 = hw::rdtsc();
    encode::rate_from_window(t1 - t0, elapsed, encode::PIT_HZ)
        .filter(|hz| (TSC_HZ_MIN..=TSC_HZ_MAX).contains(hz))
}

/// The TSC against the HPET main counter (boot identity map: called before
/// the kernel tables exist).
fn rate_hpet(ms: u32) -> Option<u64> {
    let hpet = platform().acpi.hpet?;
    let base = hpet.addr as usize;
    // SAFETY: the HPET block from the ACPI HPET table, identity-mapped by
    // boot.S; GCAP_ID 0x0, GEN_CONF 0x10, MAIN_COUNTER 0xF0.
    let (cap, conf) = unsafe {
        (core::ptr::read_volatile(base as *const u64), core::ptr::read_volatile((base + 0x10) as *const u64))
    };
    let hz = encode::hpet_hz((cap >> 32) as u32)?;
    let wide = cap & (1 << 13) != 0;
    // SAFETY: as above; ENABLE_CNF (bit 0) starts the main counter.
    unsafe { core::ptr::write_volatile((base + 0x10) as *mut u64, conf | 1) };
    let read = || {
        // SAFETY: as above.
        let v = unsafe { core::ptr::read_volatile((base + 0xF0) as *const u64) };
        if wide { v } else { v & 0xFFFF_FFFF }
    };
    let want = hz * ms as u64 / 1000;
    let c0 = read();
    let t0 = hw::rdtsc();
    let mut spins: u64 = 0;
    let elapsed = loop {
        let d = if wide { read().wrapping_sub(c0) } else { (read().wrapping_sub(c0)) & 0xFFFF_FFFF };
        if d >= want {
            break d;
        }
        spins += 1;
        if spins > 1 << 24 {
            break 0;
        }
    };
    let t1 = hw::rdtsc();
    // SAFETY: as above: the configuration as found.
    unsafe { core::ptr::write_volatile((base + 0x10) as *mut u64, conf) };
    encode::rate_from_window(t1 - t0, elapsed, hz).filter(|hz| (TSC_HZ_MIN..=TSC_HZ_MAX).contains(hz))
}

/// Find the TSC rate and switch the clock to it (boot CPU, once, interrupts
/// off, before any AP).
pub fn calibrate() -> TscSource {
    let ms = azos_limits::X86_TSC_CALIBRATE_MS as u32;
    let trust_cpuid = azos_limits::X86_TSC_FREQ_CPUID;
    let found = None
        .or_else(|| trust_cpuid.then(rate_cpuid15).flatten().map(|hz| (hz, TscSource::Cpuid15)))
        .or_else(|| trust_cpuid.then(rate_hypervisor).flatten().map(|hz| (hz, TscSource::Hypervisor)))
        .or_else(|| azos_limits::X86_HPET.then(|| rate_hpet(ms)).flatten().map(|hz| (hz, TscSource::Hpet)))
        .or_else(|| rate_pit(ms).map(|hz| (hz, TscSource::Pit)))
        .or_else(|| rate_cpuid16().map(|hz| (hz, TscSource::Cpuid16)));
    let (hz, src) = found.unwrap_or((TICK_HZ, TscSource::Assumed));
    set_rate(hz);
    SOURCE.store(src as u8, Ordering::Relaxed);
    src
}

fn set_rate(hz: u64) {
    let (Some(to_ticks), Some(to_tsc)) = (Scale::new(hz, TICK_HZ), Scale::new(TICK_HZ, hz)) else {
        return;
    };
    // Continuity: the clock goes on from where the old scale had it.
    let now = now_ticks();
    BASE_TSC.store(hw::rdtsc(), Ordering::Relaxed);
    BASE_TICKS.store(now, Ordering::Relaxed);
    TO_TICKS.store(to_ticks.mult, Ordering::Relaxed);
    TO_TSC.store(to_tsc.mult, Ordering::Relaxed);
    TSC_HZ.store(hz, Ordering::Relaxed);
}

/// TSC-deadline or LAPIC one-shot, for every CPU (boot CPU, once).
pub fn select_mode() -> bool {
    let present = cpuid(1, 0).2 & (1 << 24) != 0;
    let d = azos_arch_api::isa::x86_64::TSC_DEADLINE.gate(present);
    DEADLINE_MODE.store(d, Ordering::Relaxed);
    d
}

pub fn deadline_mode() -> bool {
    DEADLINE_MODE.load(Ordering::Relaxed)
}

/// The LAPIC divide (Kconfig `X86_LAPIC_TIMER_DIVIDE`).
const DIVIDE: u32 = azos_limits::X86_LAPIC_TIMER_DIVIDE as u32;
const TDCR: u32 = match encode::tdcr(DIVIDE) {
    Some(v) => v,
    None => panic!("X86_LAPIC_TIMER_DIVIDE must be a power of two from 1 to 128"),
};

/// Measure the LAPIC timer's count rate against the TSC (boot CPU, LAPIC
/// on, one-shot mode only). Returns the rate in Hz.
pub fn calibrate_lapic() -> Option<u64> {
    use crate::apic;
    use crate::encode::{LAPIC_LVT_TIMER, LAPIC_TIMER_CURRENT, LAPIC_TIMER_DIVIDE, LAPIC_TIMER_INIT};
    apic::write(LAPIC_TIMER_DIVIDE, TDCR);
    apic::write(LAPIC_LVT_TIMER, encode::lvt_timer(TIMER_VECTOR, TimerMode::OneShot, true));
    apic::write(LAPIC_TIMER_INIT, u32::MAX);
    let t0 = hw::rdtsc();
    udelay(azos_limits::X86_TSC_CALIBRATE_MS.saturating_mul(1000));
    let left = apic::read(LAPIC_TIMER_CURRENT);
    let t1 = hw::rdtsc();
    apic::write(LAPIC_TIMER_INIT, 0);
    let counted = (u32::MAX - left) as u64;
    let hz = encode::rate_from_window(counted, t1 - t0, tsc_hz().max(1))?;
    let scale = Scale::new(TICK_HZ, hz)?;
    LAPIC_HZ.store(hz, Ordering::Relaxed);
    TO_LAPIC.store(scale.mult, Ordering::Relaxed);
    Some(hz)
}

pub fn lapic_hz() -> u64 {
    LAPIC_HZ.load(Ordering::Relaxed)
}

/// This CPU's LVT timer in the chosen mode, unmasked, nothing armed.
pub fn init_local() {
    use crate::encode::{LAPIC_LVT_TIMER, LAPIC_TIMER_DIVIDE};
    if deadline_mode() {
        crate::apic::write(LAPIC_LVT_TIMER, encode::lvt_timer(TIMER_VECTOR, TimerMode::TscDeadline, false));
        // SDM 11.5.4.1: order the LVT write before the first deadline write.
        // SAFETY: fences only.
        unsafe { core::arch::asm!("mfence", "lfence", options(nostack, preserves_flags)) };
    } else {
        crate::apic::write(LAPIC_TIMER_DIVIDE, TDCR);
        crate::apic::write(LAPIC_LVT_TIMER, encode::lvt_timer(TIMER_VECTOR, TimerMode::OneShot, false));
    }
}

/// Fire `TIMER_VECTOR` on this CPU at clock tick `deadline` (a past one
/// fires at once). `Interrupts::set_timer_deadline`.
#[inline]
pub fn set_deadline(deadline: u64) {
    if deadline_mode() {
        // 0 would disarm.
        hw::wrmsr(TSC_DEADLINE_MSR, ticks_to_tsc(deadline).max(1));
    } else {
        let delta = deadline.saturating_sub(now_ticks());
        let scale = Scale { mult: TO_LAPIC.load(Ordering::Relaxed) };
        let count = scale.apply_ceil(delta).clamp(1, u32::MAX as u64) as u32;
        crate::apic::write(crate::encode::LAPIC_TIMER_INIT, count);
    }
}

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
//! `X86_HPET`), the ACPI PM timer (FADT, Kconfig `X86_PMTIMER`) or the PIT,
//! in that order, over `X86_TSC_CALIBRATE_MS`, else CPUID 16H's nominal base
//! frequency. Until then the scale is 1:1; the switch keeps
//! the clock continuous (`base_*`), and it happens once, single-threaded.
//!
//! **The clocksource.** The clock is the TSC only while the TSC can be
//! trusted with time ([`encode::tsc_is_clock`], Kconfig `X86_TSC_CLOCK`):
//! otherwise it is the *reference* ([`find_reference`]: the HPET main
//! counter, else the ACPI PM timer), its count extended past its wraps
//! ([`encode::extend`]) and scaled to ticks the same way. While the TSC is
//! the clock, the `tsc-watchdog` task (Kconfig `X86_TSC_WATCHDOG`,
//! kernel/src/entry/x86_64/ext/tsc_watchdog.rs) compares it with the
//! reference ([`watch`]) and on a drift [`demote`]s it, as Linux's
//! clocksource watchdog does. Either switch keeps the clock continuous and
//! happens at most once a boot; `now_ticks` pays one load and a branch for
//! it.
//!
//! **The timer** fires `TIMER_VECTOR` at a deadline in clock ticks: the
//! TSC-deadline MSR when the CPU has it and Kconfig `X86_TSC_DEADLINE`
//! allows it (the deadline converted back to TSC, rounded up), else the
//! LAPIC one-shot counter, its rate measured against the TSC by
//! [`calibrate_lapic`].

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use crate::irq::encode::{self, Scale, TimerMode, TIMER_VECTOR};
pub use crate::irq::encode::{Clocksource, Watch};
use crate::cpu;
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

/// The counter `now_ticks` reads (`Clocksource`). Stored with Release after
/// the `CLK_*` words, so a reader that sees it sees them.
static CLOCK: AtomicU8 = AtomicU8::new(Clocksource::Tsc as u8);
/// The reference (`Clocksource::Tsc` = none): what it is, where (the HPET
/// block's address or the PM timer's port), its rate and its valid bits.
/// Written once, by `calibrate`.
static REF_KIND: AtomicU8 = AtomicU8::new(Clocksource::Tsc as u8);
static REF_AT: AtomicUsize = AtomicUsize::new(0);
static REF_HZ: AtomicU64 = AtomicU64::new(0);
static REF_MASK: AtomicU64 = AtomicU64::new(0);
/// The newest extended reference count any CPU read (`encode::extend`).
static REF_LAST: AtomicU64 = AtomicU64::new(0);
/// The reference as the clock: `ticks = CLK_TICKS + (count - CLK_BASE) *
/// CLK_MULT >> 32`.
static CLK_BASE: AtomicU64 = AtomicU64::new(0);
static CLK_TICKS: AtomicU64 = AtomicU64::new(0);
static CLK_MULT: AtomicU64 = AtomicU64::new(0);

/// HPET registers (IA-PC HPET 1.0a §2.3): GCAP_ID, GEN_CONF, MAIN_COUNTER.
const HPET_GCAP: usize = 0x0;
const HPET_CONF: usize = 0x10;
const HPET_COUNTER: usize = 0xF0;

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
    PmTimer = 6,
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
            TscSource::PmTimer => "ACPI PM timer",
        }
    }
    fn from_u8(v: u8) -> Self {
        match v {
            1 => TscSource::Cpuid15,
            2 => TscSource::Hypervisor,
            3 => TscSource::Hpet,
            4 => TscSource::Pit,
            5 => TscSource::Cpuid16,
            6 => TscSource::PmTimer,
            _ => TscSource::Assumed,
        }
    }
}

/// The clock, in TIMER_FREQ ticks.
#[inline(always)]
pub fn now_ticks() -> u64 {
    if CLOCK.load(Ordering::Acquire) != Clocksource::Tsc as u8 {
        return reference_ticks();
    }
    let tsc = cpu::rdtsc();
    let scale = Scale { mult: TO_TICKS.load(Ordering::Relaxed) };
    BASE_TICKS.load(Ordering::Relaxed)
        .wrapping_add(scale.apply(tsc.wrapping_sub(BASE_TSC.load(Ordering::Relaxed))))
}

/// The clock's conversion as ring 3 applies it (the vDSO's counter scale):
/// `(TSC at base, ticks at base, 32.32 multiplier)`, so that
/// `base_ticks + ((tsc - base_tsc) * mult >> 32)` is [`now_ticks`].
pub fn counter_scale() -> (u64, u64, u64) {
    (BASE_TSC.load(Ordering::Relaxed), BASE_TICKS.load(Ordering::Relaxed), TO_TICKS.load(Ordering::Relaxed))
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

/// The counter the clock reads.
pub fn clock() -> Clocksource {
    Clocksource::from_u8(CLOCK.load(Ordering::Acquire))
}

/// The reference the TSC is checked against and falls back to, if the
/// board has one.
pub fn reference() -> Option<Clocksource> {
    match Clocksource::from_u8(REF_KIND.load(Ordering::Relaxed)) {
        Clocksource::Tsc => None,
        r => Some(r),
    }
}

/// Does the reference wrap within a boot? A 24-bit or 32-bit counter does;
/// a 64-bit HPET does not.
pub fn reference_wraps() -> bool {
    reference().is_some() && REF_MASK.load(Ordering::Relaxed) != u64::MAX
}

/// One raw read of the reference.
fn ref_read() -> u64 {
    let at = REF_AT.load(Ordering::Relaxed);
    let raw = match Clocksource::from_u8(REF_KIND.load(Ordering::Relaxed)) {
        // SAFETY: the HPET block from the ACPI HPET table, identity-mapped
        // by boot.S and then by the kernel tables' device windows.
        Clocksource::Hpet => unsafe { core::ptr::read_volatile((at + HPET_COUNTER) as *const u64) },
        Clocksource::PmTimer => cpu::inl(at as u16) as u64,
        Clocksource::Tsc => 0,
    };
    raw & REF_MASK.load(Ordering::Relaxed)
}

/// The reference's count extended past its wraps (any CPU, any context).
fn ref_count() -> u64 {
    let mask = REF_MASK.load(Ordering::Relaxed);
    if mask == u64::MAX {
        return ref_read();
    }
    loop {
        // The read after the load: a later CPU's newer count makes this
        // one's read the older, never the other way round.
        let last = REF_LAST.load(Ordering::Acquire);
        let Some(next) = encode::extend(last, ref_read(), mask) else {
            return last;
        };
        if next == last || REF_LAST.compare_exchange(last, next, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return next;
        }
    }
}

/// The clock when it is the reference (out of `now_ticks`' line).
#[inline(never)]
fn reference_ticks() -> u64 {
    let scale = Scale { mult: CLK_MULT.load(Ordering::Relaxed) };
    CLK_TICKS.load(Ordering::Relaxed).wrapping_add(scale.apply(ref_count().wrapping_sub(CLK_BASE.load(Ordering::Relaxed))))
}

/// The TSC value `us` microseconds from now (for spin delays before and
/// after calibration: an uncalibrated TSC is taken at TIMER_FREQ).
pub fn tsc_after_us(us: u64) -> u64 {
    let hz = match tsc_hz() { 0 => TICK_HZ, hz => hz };
    cpu::rdtsc().saturating_add((us as u128 * hz as u128 / 1_000_000) as u64)
}

/// Spin `us` microseconds on the TSC.
pub fn udelay(us: u64) {
    let end = tsc_after_us(us);
    while cpu::rdtsc() < end {
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

/// The PIT's channel 0 data port and its mode register (which every channel
/// shares: a command's top two bits name its channel).
const PIT_CH0: u16 = 0x40;
const PIT_MODE: u16 = 0x43;

/// The TSC against the PIT's channel 0, read through the latch command:
/// its gate is always on, unlike channel 2's, which hangs off port 0x61 and
/// a PC speaker QEMU microvm does not have. Mode 0 from 0xFFFF counts down
/// once; IRQ 0 stays masked (interrupts are off and the IOAPIC pin masked).
fn rate_pit(ms: u32) -> Option<u64> {
    let want = encode::pit_count_for_ms(ms)? as u64;
    let read = || {
        cpu::outb(PIT_MODE, 0x00); // latch channel 0
        let lo = cpu::inb(PIT_CH0) as u64;
        let hi = cpu::inb(PIT_CH0) as u64;
        lo | hi << 8
    };
    cpu::outb(PIT_MODE, 0x30); // channel 0, lobyte/hibyte, mode 0, binary
    cpu::outb(PIT_CH0, 0xFF);
    cpu::outb(PIT_CH0, 0xFF);
    let c0 = read();
    let t0 = cpu::rdtsc();
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
    let t1 = cpu::rdtsc();
    encode::rate_from_window(t1 - t0, elapsed, encode::PIT_HZ)
        .filter(|hz| (TSC_HZ_MIN..=TSC_HZ_MAX).contains(hz))
}

/// The TSC against the HPET main counter (boot identity map: called before
/// the kernel tables exist).
fn rate_hpet(ms: u32) -> Option<u64> {
    let hpet = platform().acpi.hpet?;
    let base = hpet.addr as usize;
    // SAFETY: the HPET block from the ACPI HPET table, identity-mapped by
    // boot.S (`HPET_*`).
    let (cap, conf) = unsafe {
        (core::ptr::read_volatile((base + HPET_GCAP) as *const u64), core::ptr::read_volatile((base + HPET_CONF) as *const u64))
    };
    let hz = encode::hpet_hz((cap >> 32) as u32)?;
    let wide = cap & (1 << 13) != 0;
    // SAFETY: as above; ENABLE_CNF (bit 0) starts the main counter.
    unsafe { core::ptr::write_volatile((base + HPET_CONF) as *mut u64, conf | 1) };
    let read = || {
        // SAFETY: as above.
        let v = unsafe { core::ptr::read_volatile((base + HPET_COUNTER) as *const u64) };
        if wide { v } else { v & 0xFFFF_FFFF }
    };
    let want = hz * ms as u64 / 1000;
    let c0 = read();
    let t0 = cpu::rdtsc();
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
    let t1 = cpu::rdtsc();
    // SAFETY: as above: the configuration as found.
    unsafe { core::ptr::write_volatile((base + HPET_CONF) as *mut u64, conf) };
    encode::rate_from_window(t1 - t0, elapsed, hz).filter(|hz| (TSC_HZ_MIN..=TSC_HZ_MAX).contains(hz))
}

/// The TSC against the ACPI PM timer (FADT `PM_TMR_BLK`, an I/O port): a
/// 3.579545 MHz counter, 24 or 32 bits, that runs in every C-state and that
/// every ACPI PC has when a firmware hides the HPET and the PIT is gone.
/// Port I/O, so it needs no mapping.
fn rate_pmtimer(ms: u32) -> Option<u64> {
    let f = platform().acpi.fadt?;
    if f.pm_tmr_port == 0 {
        return None;
    }
    let port = f.pm_tmr_port;
    // The counter the clock was measured on is the kernel's: no ring-3 grant
    // may open it (a dword: four ports).
    azos_arch_api::ioport::reserve(port, port.saturating_add(3));
    let want = encode::pmtmr_ticks_for_ms(ms)?;
    let read = || cpu::inl(port);
    let c0 = read();
    let t0 = cpu::rdtsc();
    let mut spins: u64 = 0;
    let elapsed = loop {
        let d = encode::pmtmr_elapsed(c0, read(), f.pm_tmr_wide);
        if d >= want {
            break d;
        }
        spins += 1;
        // A counter that does not move (a port nothing answers reads
        // all-ones) never reaches the window.
        if spins > 1 << 22 {
            return None;
        }
    };
    let t1 = cpu::rdtsc();
    encode::rate_from_window(t1 - t0, elapsed as u64, encode::PMTMR_HZ)
        .filter(|hz| (TSC_HZ_MIN..=TSC_HZ_MAX).contains(hz))
}

/// The clocksource decision for this CPU and Kconfig `X86_INVARIANT_TSC`.
pub fn clock_plan() -> encode::ClockPlan {
    use azos_arch_api::isa::{x86_64::INVARIANT_TSC as P, ExtPolicy};
    encode::clock_plan(P.allowed(), P == ExtPolicy::Require, invariant_tsc())
}

/// Find the TSC rate and switch the clock to it (boot CPU, once, interrupts
/// off, before any AP). Without an invariant TSC (or under `n`) the rates
/// CPUID and the hypervisor state are not taken: HPET, then PIT, measure it,
/// and CPUID 16H's nominal rate is the last resort ([`encode::ClockPlan`]).
/// Then the reference is found, and it becomes the clock when the TSC may
/// not be ([`encode::tsc_is_clock`]).
///
/// The PIT's channel 0 is the kernel's whichever source wins (its line, IRQ
/// 0, stays masked for good): its data port is reserved, and no ring-3 grant
/// may open it. The mode register (0x43) is not: channel 2, the PC speaker,
/// is programmed through it too, and nothing reads channel 0 after this
/// boot-time measurement (`azos_ipc::ioport_cap` has the rule).
pub fn calibrate() -> TscSource {
    azos_arch_api::ioport::reserve(PIT_CH0, PIT_CH0);
    let ms = azos_limits::X86_TSC_CALIBRATE_MS as u32;
    let stated = clock_plan() == encode::ClockPlan::Stated;
    let trust_cpuid = azos_limits::X86_TSC_FREQ_CPUID && stated;
    let found = None
        .or_else(|| trust_cpuid.then(rate_cpuid15).flatten().map(|hz| (hz, TscSource::Cpuid15)))
        .or_else(|| trust_cpuid.then(rate_hypervisor).flatten().map(|hz| (hz, TscSource::Hypervisor)))
        .or_else(|| azos_limits::X86_HPET.then(|| rate_hpet(ms)).flatten().map(|hz| (hz, TscSource::Hpet)))
        .or_else(|| azos_limits::X86_PMTIMER.then(|| rate_pmtimer(ms)).flatten().map(|hz| (hz, TscSource::PmTimer)))
        .or_else(|| rate_pit(ms).map(|hz| (hz, TscSource::Pit)))
        .or_else(|| rate_cpuid16().map(|hz| (hz, TscSource::Cpuid16)));
    let (hz, src) = found.unwrap_or((TICK_HZ, TscSource::Assumed));
    set_rate(hz);
    SOURCE.store(src as u8, Ordering::Relaxed);
    find_reference();
    if !encode::tsc_is_clock(azos_limits::X86_TSC_CLOCK_ALWAYS, clock_plan(), reference().is_some()) {
        switch_to_reference();
    }
    src
}

/// Publish the reference (from `calibrate`): the HPET (Kconfig `X86_HPET`)
/// with its main counter left running, else the PM timer (`X86_PMTIMER`),
/// each only if its count moves. The PIT is none: its 16-bit count wraps
/// every 55 ms.
fn find_reference() {
    let p = platform();
    let hpet = azos_limits::X86_HPET.then_some(p.acpi.hpet).flatten().and_then(|h| {
        let base = h.addr as usize;
        // SAFETY: the HPET block from the ACPI HPET table, identity-mapped
        // by boot.S.
        let cap = unsafe { core::ptr::read_volatile((base + HPET_GCAP) as *const u64) };
        let hz = encode::hpet_hz((cap >> 32) as u32)?;
        // SAFETY: as above; ENABLE_CNF (bit 0) starts the main counter, and
        // nothing stops it after this.
        unsafe {
            let conf = core::ptr::read_volatile((base + HPET_CONF) as *const u64);
            core::ptr::write_volatile((base + HPET_CONF) as *mut u64, conf | 1);
        }
        Some((Clocksource::Hpet, base, hz, if cap & (1 << 13) != 0 { u64::MAX } else { 0xFFFF_FFFF }))
    });
    let pmt = || {
        let f = p.acpi.fadt.filter(|f| azos_limits::X86_PMTIMER && f.pm_tmr_port != 0)?;
        Some((Clocksource::PmTimer, f.pm_tmr_port as usize, encode::PMTMR_HZ, encode::pmtmr_mask(f.pm_tmr_wide) as u64))
    };
    for (kind, at, hz, mask) in [hpet, pmt()].into_iter().flatten() {
        REF_AT.store(at, Ordering::Relaxed);
        REF_HZ.store(hz, Ordering::Relaxed);
        REF_MASK.store(mask, Ordering::Relaxed);
        REF_KIND.store(kind as u8, Ordering::Relaxed);
        // A counter that does not move (a port nothing answers reads
        // all-ones) is no reference.
        let c0 = ref_read();
        if (0..1u32 << 16).any(|_| ref_read() != c0) {
            return;
        }
    }
    REF_KIND.store(Clocksource::Tsc as u8, Ordering::Relaxed);
}

/// Make the reference the clock, going on from the TSC's reading of now.
/// Interrupts off on this CPU; other CPUs may be reading the clock.
fn switch_to_reference() {
    let (Some(kind), Some(scale)) = (reference(), Scale::new(REF_HZ.load(Ordering::Relaxed), TICK_HZ)) else {
        return;
    };
    let ticks = now_ticks();
    let count = ref_read();
    REF_LAST.store(count, Ordering::Relaxed);
    CLK_BASE.store(count, Ordering::Relaxed);
    CLK_TICKS.store(ticks, Ordering::Relaxed);
    CLK_MULT.store(scale.mult, Ordering::Relaxed);
    CLOCK.store(kind as u8, Ordering::Release);
}

/// Demote the TSC: the reference is the clock for the rest of the boot
/// (the `tsc-watchdog` task, on a drift). Returns the new clock, or `None`
/// when the TSC was not the clock or there is no reference.
pub fn demote() -> Option<Clocksource> {
    if clock() != Clocksource::Tsc {
        return None;
    }
    let on = cpu::rflags() & (1 << 9) != 0;
    cpu::cli();
    switch_to_reference();
    if on {
        cpu::sti();
    }
    Some(clock()).filter(|&c| c != Clocksource::Tsc)
}

/// The watchdog's state between two checks: the TSC and the reference at
/// the last good read.
pub struct Watchdog {
    tsc: u64,
    count: u64,
    primed: bool,
}

impl Watchdog {
    pub const fn new() -> Self {
        Watchdog { tsc: 0, count: 0, primed: false }
    }
}

impl Default for Watchdog {
    fn default() -> Self {
        Self::new()
    }
}

/// The drift bound in ppm (Kconfig `X86_TSC_WATCHDOG_PPM`).
pub const fn watch_bound_ppm() -> u64 {
    azos_limits::X86_TSC_WATCHDOG_PPM as u64
}

/// One watchdog check (Linux's `watchdog_check_freq`): the reference read
/// on both sides of a TSC read with interrupts off, compared with the last
/// good read. A read whose window took more than a quarter of the bound
/// over the interval is retried, three times, then the check is skipped and
/// the next one starts afresh. `inject_ppm` makes the TSC run that much
/// fast (the gate's injected skew). `Rebase` for the first check.
pub fn watch(w: &mut Watchdog, inject_ppm: u64) -> Watch {
    let (hz, mask) = (REF_HZ.load(Ordering::Relaxed), REF_MASK.load(Ordering::Relaxed));
    let ppm = watch_bound_ppm();
    let interval_ns = azos_limits::X86_TSC_WATCHDOG_MS as u64 * 1_000_000;
    let window_max = (interval_ns as u128 * ppm as u128 / 4_000_000) as u64;
    for _ in 0..3 {
        let on = cpu::rflags() & (1 << 9) != 0;
        cpu::cli();
        let c0 = ref_count();
        let t = cpu::rdtsc();
        let c1 = ref_count();
        if on {
            cpu::sti();
        }
        let window = encode::count_ns(c1.wrapping_sub(c0), hz);
        if window > window_max {
            continue;
        }
        let last = core::mem::replace(w, Watchdog { tsc: t, count: c0, primed: true });
        if !last.primed {
            return Watch::Rebase;
        }
        let tsc_ns = encode::count_ns(t.wrapping_sub(last.tsc), tsc_hz());
        let tsc_ns = tsc_ns.saturating_add((tsc_ns as u128 * inject_ppm as u128 / 1_000_000) as u64);
        let ref_ns = encode::count_ns(c0.wrapping_sub(last.count), hz);
        return encode::watch(tsc_ns, ref_ns, window, encode::wrap_span_ns(mask, hz), ppm);
    }
    w.primed = false;
    Watch::Rebase
}

fn set_rate(hz: u64) {
    let (Some(to_ticks), Some(to_tsc)) = (Scale::new(hz, TICK_HZ), Scale::new(TICK_HZ, hz)) else {
        return;
    };
    // Continuity: the clock goes on from where the old scale had it.
    let now = now_ticks();
    BASE_TSC.store(cpu::rdtsc(), Ordering::Relaxed);
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
    use crate::irq::apic;
    use crate::irq::encode::{LAPIC_LVT_TIMER, LAPIC_TIMER_CURRENT, LAPIC_TIMER_DIVIDE, LAPIC_TIMER_INIT};
    apic::write(LAPIC_TIMER_DIVIDE, TDCR);
    apic::write(LAPIC_LVT_TIMER, encode::lvt_timer(TIMER_VECTOR, TimerMode::OneShot, true));
    apic::write(LAPIC_TIMER_INIT, u32::MAX);
    let t0 = cpu::rdtsc();
    udelay(azos_limits::X86_TSC_CALIBRATE_MS.saturating_mul(1000));
    let left = apic::read(LAPIC_TIMER_CURRENT);
    let t1 = cpu::rdtsc();
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
    use crate::irq::encode::{LAPIC_LVT_TIMER, LAPIC_TIMER_DIVIDE};
    if deadline_mode() {
        crate::irq::apic::write(LAPIC_LVT_TIMER, encode::lvt_timer(TIMER_VECTOR, TimerMode::TscDeadline, false));
        // SDM 11.5.4.1: order the LVT write before the first deadline write.
        // SAFETY: fences only.
        unsafe { core::arch::asm!("mfence", "lfence", options(nostack, preserves_flags)) };
    } else {
        crate::irq::apic::write(LAPIC_TIMER_DIVIDE, TDCR);
        crate::irq::apic::write(LAPIC_LVT_TIMER, encode::lvt_timer(TIMER_VECTOR, TimerMode::OneShot, false));
    }
}

/// Fire `TIMER_VECTOR` on this CPU at clock tick `deadline` (a past one
/// fires at once). `Interrupts::set_timer_deadline`.
#[inline]
pub fn set_deadline(deadline: u64) {
    if deadline_mode() {
        let tsc = if clock() == Clocksource::Tsc {
            ticks_to_tsc(deadline)
        } else {
            // The clock is not the TSC: convert the time left, so a TSC
            // that drifts misses by its drift over one timeout, not over the
            // boot (Linux keeps its lapic-deadline timer the same way).
            let scale = Scale { mult: TO_TSC.load(Ordering::Relaxed) };
            cpu::rdtsc().saturating_add(scale.apply_ceil(deadline.saturating_sub(now_ticks())))
        };
        // 0 would disarm.
        cpu::wrmsr(TSC_DEADLINE_MSR, tsc.max(1));
    } else {
        let delta = deadline.saturating_sub(now_ticks());
        let scale = Scale { mult: TO_LAPIC.load(Ordering::Relaxed) };
        let count = scale.apply_ceil(delta).clamp(1, u32::MAX as u64) as u32;
        crate::irq::apic::write(crate::irq::encode::LAPIC_TIMER_INIT, count);
    }
}

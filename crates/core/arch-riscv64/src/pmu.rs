// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The riscv64 counters behind [`azos_arch_api::Pmu`], Kconfig `RV_PMU`.
//!
//! Cycles and instructions are the Zicntr `cycle` and `instret` CSRs, which
//! S-mode reads while `mcounteren` allows (OpenSBI sets it). The boot runs
//! them once under a private trap vector ([`select`]): a firmware that
//! withholds one is not trapped on later, the figure just reads 0. A counter
//! that does not move is dropped the same way as on the other ISAs
//! ([`verify`]).
//!
//! [`Pmu::event`](azos_arch_api::Pmu::event) takes a hardware counter from the
//! SBI PMU extension: `counter_config_matching` picks an `hpmcounterN` that
//! can count the SBI event index `sel` and starts it from 0, and the counter
//! is read as that CSR. QEMU virt has no programmable counter (its OpenSBI
//! answers the extension with only cycle, time and instret, or not at all):
//! `events=0` on the boot line.
//!
//! Overflow sampling (the profiler, Kconfig `PROFILER_PMU`) takes a second
//! `hpmcounterN` the same way, for CPU_CYCLES, and needs Sscofpmf (Kconfig
//! `RV_SSCOFPMF`): the counter's overflow sets its `scountovf` bit and raises
//! the local counter-overflow interrupt (LCOFI, `scause` 13, `sie.LCOFIE`).
//! The probe is cpu@0's `riscv,isa` token, then one trap-safe `scountovf`
//! read ([`sscofpmf_select`]). The firmware owns the counter's event register
//! and its OF bit: S-mode loads the counter through `counter_start` (which
//! clears OF, but only while `sip.LCOFIP` is clear: the interrupt is
//! acknowledged first). QEMU virt has it with `-cpu rv64,sscofpmf=on`.
//!
//! Ring 3 reads what Kconfig `PMU_USER` allows through `scounteren`
//! (`TM` always, `CY`/`IR` for a live counter); `trap_init` leaves the clock
//! alone and [`start_this_cpu`], on every hart, writes the rest. Before this
//! file a hart that was not the boot hart left `scounteren` at its reset
//! value.

use azos_arch_api::isa::{riscv64 as policy, ExtPolicy};
// The cross-ISA helpers, under the ISA's own module (`azos_arch::pmu`).
pub use azos_arch_api::pmu::{advanced, delta, mask, rate_per_us, PmuCaps, Source};
use azos_arch_api::pmu as api;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicU8, AtomicUsize, Ordering};

/// `scounteren` before the probe has run: the clock for ring 3 and nothing else.
pub const SCOUNTEREN_BOOT: usize = api::rv_scounteren(false, false);

/// Counters are read at all (Kconfig `RV_PMU` is not `n`).
static ON: AtomicBool = AtomicBool::new(false);
/// `cycle` / `instret` readable and moving ([`select`], [`verify`]).
static CYC_OK: AtomicBool = AtomicBool::new(false);
static INS_OK: AtomicBool = AtomicBool::new(false);
/// The probe's two readable bits (bit 0 `cycle`, bit 1 `instret`).
static READABLE: AtomicU8 = AtomicU8::new(0);
/// Ring 3 may read them (Kconfig `PMU_USER`, with the counter live).
static USER_C: AtomicBool = AtomicBool::new(false);
static USER_I: AtomicBool = AtomicBool::new(false);
/// SBI counter indices [`event`](azos_arch_api::Pmu::event) may be given
/// (bit n: counter n), and the width of the first hardware one.
static EVENT_MASK: AtomicUsize = AtomicUsize::new(0);
static EVENT_BITS: AtomicU8 = AtomicU8::new(64);

/// Per hart, the event its counter counts: `sel` (`u64::MAX`: none), the
/// counter's SBI index and its CSR number.
struct Slot {
    sel: AtomicU64,
    idx: AtomicU8,
    csr: AtomicU16,
}

const NO_EVENT: u64 = u64::MAX;
static SLOTS: [Slot; azos_limits::NR_CPUS] = [const {
    Slot { sel: AtomicU64::new(NO_EVENT), idx: AtomicU8::new(0), csr: AtomicU16::new(0) }
}; azos_limits::NR_CPUS];

/// Sscofpmf is in use ([`sscofpmf_select`]).
static SSCOFPMF: AtomicBool = AtomicBool::new(false);

/// Per hart, the overflow-sampling counter: its SBI index (`NO_SAMPLE`:
/// disarmed) and its width, from `counter_get_info`.
struct Sampler {
    idx: AtomicU8,
    bits: AtomicU8,
}

const NO_SAMPLE: u8 = u8::MAX;
static SAMPLERS: [Sampler; azos_limits::NR_CPUS] = [const {
    Sampler { idx: AtomicU8::new(NO_SAMPLE), bits: AtomicU8::new(0) }
}; azos_limits::NR_CPUS];

/// Boot, the boot hart, before [`start_this_cpu`]: probe what the firmware
/// gives, unless Kconfig says `n`. Returns whether a programmable hardware
/// counter exists (the `[ISA]` line's `pmu` row; `cycle` and `instret` are
/// baseline and do not count toward `require`).
pub fn select() -> bool {
    if matches!(policy::PMU, ExtPolicy::Never) {
        return false;
    }
    ON.store(true, Ordering::Relaxed);
    READABLE.store(csr_probe(), Ordering::Relaxed);
    let firmware = crate::firmware::probe_extension(api::SBI_EXT_PMU) != 0;
    if !firmware {
        return false;
    }
    let num = sbi(api::SBI_PMU_NUM_COUNTERS, [0; 6]).unwrap_or(0).max(0) as usize;
    let Some((_, first)) = api::rv_first_hw_counter(num, |idx| {
        sbi(api::SBI_PMU_COUNTER_GET_INFO, [idx, 0, 0, 0, 0, 0]).unwrap_or(isize::MIN) as u64
    }) else {
        return false;
    };
    EVENT_MASK.store(api::rv_programmable_mask(num), Ordering::Relaxed);
    EVENT_BITS.store(first.bits, Ordering::Relaxed);
    true
}

/// Boot hart, after [`select`] and before [`verify`]: Sscofpmf when Kconfig
/// `RV_SSCOFPMF` allows it (`allowed`), cpu@0's `riscv,isa` names it
/// (`claimed`) and a trap-safe read of `scountovf` succeeds (M-mode may
/// withhold the CSR). `n` executes nothing. Returns the `[ISA]` line's
/// `sscofpmf` row; sampling also needs the programmable counter [`select`]
/// found ([`PmuCaps::sample_bits`]).
pub fn sscofpmf_select(allowed: bool, claimed: bool) -> bool {
    let on = allowed && claimed && scountovf_probe();
    SSCOFPMF.store(on, Ordering::Relaxed);
    on
}

/// Is Sscofpmf in use ([`sscofpmf_select`])?
pub fn sscofpmf() -> bool {
    SSCOFPMF.load(Ordering::Relaxed)
}

/// The event selector of "mispredicted branches" for [`Pmu::event`](azos_arch_api::Pmu::event)
/// on this ISA: the boot self-test counts it over a short loop
/// (`boot::seams::pmu_report`).
pub fn branch_miss_event() -> u64 {
    api::SBI_HW_BRANCH_MISSES
}

/// Was a programmable hardware counter found ([`select`])?
pub fn present() -> bool {
    EVENT_MASK.load(Ordering::Relaxed) != 0
}

/// One SBI PMU call: the value, or `None` on an error code.
fn sbi(fid: usize, args: [usize; 6]) -> Option<isize> {
    let r = crate::firmware::sbi_call(api::SBI_EXT_PMU, fid, args);
    (r.error == 0).then_some(r.value)
}

/// This hart's `scounteren`: the clock, plus the counters ring 3 may read.
/// Every hart, boot and secondary (`secondary_irq_init`).
pub fn start_this_cpu() {
    crate::cpu::write_scounteren(api::rv_scounteren(USER_C.load(Ordering::Relaxed), USER_I.load(Ordering::Relaxed)));
}

/// Boot hart, after [`select`]: keep the counters that are readable and
/// moving, open to ring 3 the ones Kconfig `PMU_USER` allows (this hart's
/// `scounteren`; each secondary reads the flags in [`start_this_cpu`]), and
/// return the final capabilities for the boot line.
pub fn verify() -> PmuCaps {
    if ON.load(Ordering::Relaxed) {
        let readable = READABLE.load(Ordering::Relaxed);
        let (c0, i0) = (read_csr_cycle(readable & 1 != 0), read_csr_instret(readable & 2 != 0));
        for _ in 0..4096 {
            core::hint::spin_loop();
        }
        let (c1, i1) = (read_csr_cycle(readable & 1 != 0), read_csr_instret(readable & 2 != 0));
        let (cyc, ins) = (readable & 1 != 0 && api::advanced(64, c0, c1), readable & 2 != 0 && api::advanced(64, i0, i1));
        CYC_OK.store(cyc, Ordering::Relaxed);
        INS_OK.store(ins, Ordering::Relaxed);
        USER_C.store(azos_limits::PMU_USER && cyc, Ordering::Relaxed);
        USER_I.store(azos_limits::PMU_USER && ins, Ordering::Relaxed);
    }
    start_this_cpu();
    caps()
}

/// The capabilities as the boot left them.
pub fn caps() -> PmuCaps {
    let src = |ok: &AtomicBool| if ok.load(Ordering::Relaxed) { Source::Isa } else { Source::None };
    PmuCaps {
        cycles: src(&CYC_OK),
        instructions: src(&INS_OK),
        cycle_bits: 64,
        instr_bits: 64,
        events: if present() { 1 } else { 0 },
        event_bits: EVENT_BITS.load(Ordering::Relaxed),
        user_cycles: USER_C.load(Ordering::Relaxed),
        user_instructions: USER_I.load(Ordering::Relaxed),
        // The first hardware counter's width: the one `sample_arm` is given
        // is read again there.
        sample_bits: if sscofpmf() && present() { EVENT_BITS.load(Ordering::Relaxed) } else { 0 },
    }
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn read_csr_cycle(readable: bool) -> u64 {
    if !readable {
        return 0;
    }
    let v: u64;
    // SAFETY: `csr_probe` read `cycle` without a trap; no memory.
    unsafe { core::arch::asm!("rdcycle {}", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn read_csr_instret(readable: bool) -> u64 {
    if !readable {
        return 0;
    }
    let v: u64;
    // SAFETY: `csr_probe` read `instret` without a trap; no memory.
    unsafe { core::arch::asm!("rdinstret {}", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

#[cfg(not(target_arch = "riscv64"))]
fn read_csr_cycle(_readable: bool) -> u64 {
    0
}

#[cfg(not(target_arch = "riscv64"))]
fn read_csr_instret(_readable: bool) -> u64 {
    0
}

/// One trap-safe run reading `cycle` and `instret`: bit 0 set if `cycle`
/// read, bit 1 if `instret` did.
fn csr_probe() -> u8 {
    #[cfg(target_arch = "riscv64")]
    {
        // SAFETY: the routine installs its own stvec with interrupts off and
        // restores both; it only reads two CSRs; no memory.
        unsafe { azos_pmu_probe() as u8 }
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        0
    }
}

// `azos_pmu_probe() -> a0` (bit 0 `cycle` read, bit 1 `instret` read). The
// `seed.rs` probe's shape: sstatus.SIE cleared, a private stvec whose
// handler clears the bit of the access that trapped (told apart by `sepc`)
// and resumes after it, stvec and SIE restored. Clobbers t0-t4.
#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".pushsection .text.azos_pmu_probe, \"ax\"",
    ".globl azos_pmu_probe",
    ".p2align 2",
    "azos_pmu_probe:",
    "    csrrci t3, sstatus, 2",
    "    csrr   t1, stvec",
    "    la     t0, 1f",
    "    csrw   stvec, t0",
    "    li     a0, 3",
    "4:  csrr   t2, cycle",
    "5:  csrr   t2, instret",
    "2:  csrw   stvec, t1",
    "    andi   t3, t3, 2",
    "    csrs   sstatus, t3",
    "    ret",
    ".p2align 2",
    "1:  csrr   t0, sepc",
    "    la     t4, 4b",
    "    bne    t0, t4, 6f",
    "    andi   a0, a0, 2",
    "    j      7f",
    "6:  andi   a0, a0, 1",
    "7:  addi   t0, t0, 4",
    "    csrw   sepc, t0",
    "    sret",
    ".popsection",
);

#[cfg(target_arch = "riscv64")]
unsafe extern "C" {
    fn azos_pmu_probe() -> usize;
    fn azos_scountovf_probe() -> usize;
}

/// One trap-safe read of `scountovf` (CSR 0xDA0): true when it did not trap.
fn scountovf_probe() -> bool {
    #[cfg(target_arch = "riscv64")]
    {
        // SAFETY: as `csr_probe`: a private stvec with interrupts off, both
        // restored; one CSR read; no memory.
        unsafe { azos_scountovf_probe() != 0 }
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        false
    }
}

// `azos_scountovf_probe() -> a0` (1: `scountovf` read). `azos_pmu_probe`'s
// shape with one access: the handler answers 0 and resumes after it.
// Clobbers t0-t3.
#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".pushsection .text.azos_scountovf_probe, \"ax\"",
    ".globl azos_scountovf_probe",
    ".p2align 2",
    "azos_scountovf_probe:",
    "    csrrci t3, sstatus, 2",
    "    csrr   t1, stvec",
    "    la     t0, 1f",
    "    csrw   stvec, t0",
    "    li     a0, 1",
    "    csrr   t2, 0xda0",
    "    csrw   stvec, t1",
    "    andi   t3, t3, 2",
    "    csrs   sstatus, t3",
    "    ret",
    ".p2align 2",
    "1:  li     a0, 0",
    "    csrr   t0, sepc",
    "    addi   t0, t0, 4",
    "    csrw   sepc, t0",
    "    sret",
    ".popsection",
);

/// `scountovf`: bit n set when counter n's OF bit is (Sscofpmf only).
#[cfg(target_arch = "riscv64")]
fn read_scountovf() -> usize {
    let v: usize;
    // SAFETY: only reached with Sscofpmf in use (`sscofpmf_select` read it
    // without a trap); no memory.
    unsafe { core::arch::asm!("csrr {}, 0xda0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

#[cfg(not(target_arch = "riscv64"))]
fn read_scountovf() -> usize {
    0
}

/// `sip.LCOFIP` cleared: the overflow interrupt acknowledged, so the next
/// `counter_start` may clear the counter's OF bit.
#[cfg(target_arch = "riscv64")]
fn clear_lcofip() {
    // SAFETY: LCOFIP is S-mode writable under Sscofpmf; no memory.
    unsafe { core::arch::asm!("csrc sip, {}", in(reg) api::RV_SIE_LCOFIE, options(nomem, nostack)) };
}

#[cfg(not(target_arch = "riscv64"))]
fn clear_lcofip() {}

/// Load counter `idx` with the value that wraps after `period` cycles and
/// start it (`counter_start` with an initial value).
fn sample_start(idx: u8, bits: u8, period: u64) -> bool {
    sbi(api::SBI_PMU_COUNTER_START,
        [idx as usize, 1, api::SBI_PMU_START_SET_INIT_VALUE, api::sample_init(bits, period) as usize, 0, 0]).is_some()
}

/// `hpmcounter<csr - 0xC00>` by CSR number: a CSR number is an immediate in
/// the instruction, so the 29 programmable counters are 29 arms.
#[cfg(target_arch = "riscv64")]
fn read_hpm(csr: u16) -> u64 {
    macro_rules! hpm {
        ($($n:literal),*) => {
            match csr {
                $(x if x == 0xC00 + $n => {
                    let v: u64;
                    // SAFETY: the SBI firmware handed this hart `hpmcounter<N>`
                    // for an event (`event`), so S-mode may read it; no memory.
                    unsafe {
                        core::arch::asm!(concat!("csrr {}, hpmcounter", $n), out(reg) v,
                                         options(nomem, nostack, preserves_flags))
                    };
                    v
                })*
                _ => 0,
            }
        };
    }
    hpm!(3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31)
}

#[cfg(not(target_arch = "riscv64"))]
fn read_hpm(_csr: u16) -> u64 {
    0
}

impl azos_arch_api::Pmu for crate::api_impl::Riscv64 {
    fn caps(&self) -> PmuCaps {
        caps()
    }

    #[inline(always)]
    fn cycles(&self) -> u64 {
        if CYC_OK.load(Ordering::Relaxed) { read_csr_cycle(true) } else { 0 }
    }

    #[inline(always)]
    fn instructions(&self) -> u64 {
        if INS_OK.load(Ordering::Relaxed) { read_csr_instret(true) } else { 0 }
    }

    /// An `hpmcounterN` the firmware allocates for SBI event index `sel`, per
    /// hart; asking for another event stops the old counter and allocates
    /// again.
    fn event(&self, sel: u64) -> Option<u64> {
        use azos_arch_api::Cpu as _;
        let mask = EVENT_MASK.load(Ordering::Relaxed);
        if mask == 0 {
            return None;
        }
        let slot = SLOTS.get(self.hart_id())?;
        if slot.sel.load(Ordering::Relaxed) != sel {
            if slot.sel.load(Ordering::Relaxed) != NO_EVENT {
                // Stop and release the old counter (flag bit 0: reset).
                let _ = sbi(api::SBI_PMU_COUNTER_STOP, [0, 1 << slot.idx.load(Ordering::Relaxed), 1, 0, 0, 0]);
                slot.sel.store(NO_EVENT, Ordering::Relaxed);
            }
            let idx = sbi(api::SBI_PMU_COUNTER_CONFIG_MATCHING,
                          [0, mask, api::SBI_PMU_CFG_CLEAR_AND_START, sel as usize, 0, 0])? as usize;
            let info = sbi(api::SBI_PMU_COUNTER_GET_INFO, [idx, 0, 0, 0, 0, 0]).map(|v| v as u64);
            match info.and_then(|v| api::rv_counter_info(v, 64)) {
                Some(c) if idx < 32 => {
                    slot.idx.store(idx as u8, Ordering::Relaxed);
                    slot.csr.store(c.csr, Ordering::Relaxed);
                    slot.sel.store(sel, Ordering::Relaxed);
                }
                _ => {
                    // A firmware counter: not readable as a CSR. Give it back.
                    let _ = sbi(api::SBI_PMU_COUNTER_STOP, [0, 1usize << (idx & 63), 1, 0, 0, 0]);
                    return None;
                }
            }
        }
        Some(read_hpm(slot.csr.load(Ordering::Relaxed)))
    }

    /// An `hpmcounterN` the firmware allocates for CPU_CYCLES on the first
    /// arm (kept until a disarming [`sample_ack`](azos_arch_api::Pmu::sample_ack)),
    /// loaded and started, and `sie.LCOFIE` set on this hart.
    fn sample_arm(&self, period: u64) -> bool {
        use azos_arch_api::Cpu as _;
        let mask = EVENT_MASK.load(Ordering::Relaxed);
        if !sscofpmf() || mask == 0 {
            return false;
        }
        let Some(s) = SAMPLERS.get(self.hart_id()) else { return false };
        let mut idx = s.idx.load(Ordering::Relaxed);
        if idx == NO_SAMPLE {
            let Some(i) = sbi(api::SBI_PMU_COUNTER_CONFIG_MATCHING,
                              [0, mask, api::SBI_PMU_CFG_SAMPLE, api::SBI_HW_CPU_CYCLES as usize, 0, 0]) else {
                return false;
            };
            let i = i as usize;
            let info = sbi(api::SBI_PMU_COUNTER_GET_INFO, [i, 0, 0, 0, 0, 0]).map(|v| v as u64);
            match info.and_then(|v| api::rv_counter_info(v, 64)) {
                Some(c) if i < 32 => {
                    s.bits.store(c.bits, Ordering::Relaxed);
                    s.idx.store(i as u8, Ordering::Relaxed);
                    idx = i as u8;
                }
                _ => {
                    // A firmware counter raises no LCOFI: give it back.
                    let _ = sbi(api::SBI_PMU_COUNTER_STOP, [i & 63, 1, api::SBI_PMU_STOP_RESET, 0, 0, 0]);
                    return false;
                }
            }
        } else {
            // A started counter refuses `counter_start`.
            let _ = sbi(api::SBI_PMU_COUNTER_STOP, [idx as usize, 1, 0, 0, 0, 0]);
        }
        let bits = s.bits.load(Ordering::Relaxed);
        if !api::sample_period_fits(bits, period) || !sample_start(idx, bits, period) {
            let _ = self.sample_ack(None);
            return false;
        }
        crate::cpu::write_sie(crate::cpu::read_sie() | api::RV_SIE_LCOFIE);
        true
    }

    /// LCOFI: this hart's counter's `scountovf` bit, then `sip.LCOFIP`
    /// cleared and the counter stopped and restarted from the period's
    /// initial value (which clears its OF bit), or released.
    fn sample_ack(&self, rearm: Option<u64>) -> bool {
        use azos_arch_api::Cpu as _;
        let Some(s) = SAMPLERS.get(self.hart_id()) else { return false };
        let idx = s.idx.load(Ordering::Relaxed);
        if idx == NO_SAMPLE {
            clear_lcofip();
            return false;
        }
        let overflowed = read_scountovf() >> idx & 1 != 0;
        clear_lcofip();
        match rearm {
            Some(period) if overflowed => {
                let _ = sbi(api::SBI_PMU_COUNTER_STOP, [idx as usize, 1, 0, 0, 0, 0]);
                if !sample_start(idx, s.bits.load(Ordering::Relaxed), period) {
                    let _ = self.sample_ack(None);
                }
            }
            // Not this counter's interrupt: it keeps counting.
            Some(_) => {}
            None => {
                let _ = sbi(api::SBI_PMU_COUNTER_STOP, [idx as usize, 1, api::SBI_PMU_STOP_RESET, 0, 0, 0]);
                s.idx.store(NO_SAMPLE, Ordering::Relaxed);
                crate::cpu::write_sie(crate::cpu::read_sie() & !api::RV_SIE_LCOFIE);
            }
        }
        overflowed
    }
}

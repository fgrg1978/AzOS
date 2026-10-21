// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The CPU's performance counters behind one seam, the same model on every
//! ISA (`Pmu`, reached as `azos_arch::ARCH`):
//!
//! | ISA     | cycles                        | instructions                  | `event(sel)`                         | Kconfig  | Probe |
//! |---------|-------------------------------|-------------------------------|--------------------------------------|----------|-------|
//! | riscv64 | `cycle` CSR (Zicntr)          | `instret` CSR (Zicntr)        | SBI PMU: `hpmcounterN` by event idx  | RV_PMU   | SBI PMU extension (EID `PMU`) |
//! | aarch64 | `PMCCNTR_EL0`                 | `PMEVCNTR0_EL0`, INST_RETIRED | `PMEVCNTR1_EL0`, event number        | A64_PMU  | `ID_AA64DFR0_EL1.PMUVer` |
//! | x86_64  | Intel fixed 1 (CLK_UNHALTED), AMD PMC0 (event 0x76), else the TSC | Intel fixed 0 (INST_RETIRED), AMD PMC1 (event 0xC0) | Intel PMC0, AMD PMC2 (`IA32_PERFEVTSEL`/`PerfEvtSel` image) | X86_PMU | CPUID leaf 0xA (Intel), `0x80000001` ECX\[23\] / `0x80000022` (AMD) |
//!
//! What a count means, the same everywhere:
//!
//! * **Per CPU.** Every counter belongs to the CPU that runs the read. Two
//!   reads are comparable only when both ran on that CPU (interrupts or
//!   preemption off across the pair); a delta across two CPUs is garbage.
//! * **Raw and modulo `2^bits`.** A read is the counter's value, `bits` wide
//!   ([`PmuCaps::cycle_bits`], [`PmuCaps::instr_bits`]); subtract two reads
//!   with [`delta`], which survives a wrap. The 64-bit counters (riscv64,
//!   aarch64 cycles) need nothing more than `wrapping_sub`.
//! * **0 means "no counter".** [`Pmu::cycles`] and [`Pmu::instructions`]
//!   answer 0 where [`PmuCaps`] says [`Source::None`] (a hypervisor without
//!   a PMU, Kconfig `n`): a zero delta is "no measurement", the convention
//!   `azos_drv_sys::wcet` has always had.
//! * **Cycles are not time.** They stop while the core sleeps in `wfi`/`hlt`
//!   on most cores and tick at the core clock, not the timebase; the rate is
//!   measured once against the timebase (`azos_drv_sys::wcet::calibrate_cpu_freq`).
//!
//! The ISA crates read and program the hardware (`pmu.rs` at the same place
//! in each). What is pure is here, so the host tests drive it with fake
//! register words: the probes' decode of the identification words, the
//! register images they write, [`delta`] and [`rate_per_us`].

use core::fmt;

/// Where a count comes from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    /// No counter: the read answers 0.
    None,
    /// The timestamp counter standing in for a core-cycle counter (x86_64
    /// without a PMU: `rdtsc`). It ticks at the TSC rate, not the core
    /// clock. Never an instruction count.
    Timebase,
    /// The base ISA's own counter: riscv64 Zicntr `cycle`/`instret`.
    Isa,
    /// A performance-monitoring unit counter.
    Pmu,
}

impl Source {
    /// The word the `[PMU]` line prints.
    pub const fn name(self) -> &'static str {
        match self {
            Source::None => "none",
            Source::Timebase => "tsc",
            Source::Isa => "isa",
            Source::Pmu => "pmu",
        }
    }
}

/// What the boot probe found, constant after the boot (the user-access
/// flags are set per CPU by `start_this_cpu`, identically on every CPU).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PmuCaps {
    /// The cycle counter's source.
    pub cycles: Source,
    /// The retired-instruction counter's source.
    pub instructions: Source,
    /// Width of the cycle counter in bits (64 when there is none).
    pub cycle_bits: u8,
    /// Width of the instruction counter in bits (64 when there is none).
    pub instr_bits: u8,
    /// Programmable counters [`Pmu::event`] can use on this CPU (0: none).
    pub events: u8,
    /// Width of an event counter in bits (64 when there is none).
    pub event_bits: u8,
    /// Ring 3 may read the cycle counter (Kconfig `PMU_USER`, set by
    /// `start_this_cpu`): the vDSO hwcap bit follows it.
    pub user_cycles: bool,
    /// Ring 3 may read the instruction counter (as `user_cycles`).
    pub user_instructions: bool,
}

impl PmuCaps {
    /// Nothing found, nothing readable.
    pub const NONE: PmuCaps = PmuCaps {
        cycles: Source::None,
        instructions: Source::None,
        cycle_bits: 64,
        instr_bits: 64,
        events: 0,
        event_bits: 64,
        user_cycles: false,
        user_instructions: false,
    };

    /// Does the cycle counter count core cycles (not the TSC, not nothing)?
    pub const fn core_cycles(&self) -> bool {
        matches!(self.cycles, Source::Isa | Source::Pmu)
    }
}

/// The `[PMU]` boot line's tail, the same shape on every ISA
/// (`kprintln!("[PMU] x86_64 {}", caps)`):
/// `cycles=pmu/48 instret=pmu/48 events=1/48 user=cycles,instret`.
impl fmt::Display for PmuCaps {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(w, "cycles={}", self.cycles.name())?;
        if self.cycles != Source::None {
            write!(w, "/{}", self.cycle_bits)?;
        }
        write!(w, " instret={}", self.instructions.name())?;
        if self.instructions != Source::None {
            write!(w, "/{}", self.instr_bits)?;
        }
        write!(w, " events={}", self.events)?;
        if self.events != 0 {
            write!(w, "/{}", self.event_bits)?;
        }
        write!(w, " user=")?;
        match (self.user_cycles, self.user_instructions) {
            (true, true) => write!(w, "cycles,instret"),
            (true, false) => write!(w, "cycles"),
            (false, true) => write!(w, "instret"),
            (false, false) => write!(w, "none"),
        }
    }
}

/// The performance counters of the CPU that runs the call. See the module
/// doc for what a count is and which ISA reads what.
pub trait Pmu: Send + Sync {
    /// What the boot probe found. Cheap; read it at boot, not per sample.
    fn caps(&self) -> PmuCaps;

    /// This CPU's cycle counter, raw (modulo `2^cycle_bits`); 0 when
    /// [`PmuCaps::cycles`] is [`Source::None`].
    fn cycles(&self) -> u64;

    /// This CPU's retired-instruction counter, raw (modulo
    /// `2^instr_bits`); 0 when [`PmuCaps::instructions`] is [`Source::None`].
    fn instructions(&self) -> u64;

    /// This CPU's event counter for the event `sel`, or `None` when the CPU
    /// has no programmable counter (or its probe was `n`). `sel` is the ISA's
    /// own event selector: x86_64 the low word of `IA32_PERFEVTSEL` /
    /// AMD `PerfEvtSel` (event \[7:0\], unit mask \[15:8\], AMD event
    /// \[35:32\]); aarch64 the PMU event number; riscv64 the SBI event index
    /// (type \[19:16\], code \[15:0\]).
    ///
    /// One counter per CPU serves it. Asking for the event it already counts
    /// reads it; asking for another reprograms the counter and restarts it
    /// from 0, so the first read after a change is the count since that call.
    /// The reprogramming is not atomic against a second user on the same
    /// CPU: call with preemption off, and let one caller own the counter at
    /// a time (the boot self-test and a bench never overlap).
    fn event(&self, sel: u64) -> Option<u64>;
}

// ── Counter math ────────────────────────────────────────────────────────

/// The value mask of a `bits`-wide counter (`bits >= 64` is all ones).
pub const fn mask(bits: u8) -> u64 {
    if bits >= 64 { !0 } else { (1u64 << bits) - 1 }
}

/// `end - start` of two reads of one `bits`-wide counter, across a wrap
/// when `end` is below `start`. A counter wider than the value read (the
/// reads are masked by the hardware) needs this; a 64-bit one is
/// `wrapping_sub`.
pub const fn delta(bits: u8, start: u64, end: u64) -> u64 {
    end.wrapping_sub(start) & mask(bits)
}

/// Did a counter move between two reads, and by a believable amount? The
/// boot probe's liveness check: a counter that stays put (a hypervisor that
/// ignores the enable) or jumps by more than half its range (garbage) is not
/// used. `bits` is the counter width.
pub const fn advanced(bits: u8, start: u64, end: u64) -> bool {
    let d = delta(bits, start, end);
    d != 0 && d <= mask(bits) / 2
}

/// Cycles per microsecond from `cycles` counted over `elapsed_us`
/// microseconds of the timebase. Never 0: an unmeasurable interval
/// (`elapsed_us == 0`) or a counter that did not run (`cycles == 0`) is 1,
/// "a cycle is a microsecond", so a conversion never divides by 0 and a
/// broken measurement degrades to raw counts instead of a wrong figure.
pub const fn rate_per_us(cycles: u64, elapsed_us: u64) -> u64 {
    if elapsed_us == 0 {
        return 1;
    }
    let r = cycles / elapsed_us;
    if r == 0 { 1 } else { r }
}

// ── x86_64 ──────────────────────────────────────────────────────────────

/// `IA32_PMC0` (the first programmable counter, Intel).
pub const X86_MSR_PMC0: u32 = 0xC1;
/// `IA32_PERFEVTSEL0`.
pub const X86_MSR_PERFEVTSEL0: u32 = 0x186;
/// `IA32_FIXED_CTR0` (INST_RETIRED.ANY); fixed counter `n` is `+ n`.
pub const X86_MSR_FIXED_CTR0: u32 = 0x309;
/// `IA32_FIXED_CTR_CTRL`: four bits per fixed counter.
pub const X86_MSR_FIXED_CTR_CTRL: u32 = 0x38D;
/// `IA32_PERF_GLOBAL_CTRL`: PMC enables in \[n:0\], fixed enables in \[34:32\].
pub const X86_MSR_PERF_GLOBAL_CTRL: u32 = 0x38F;
/// AMD `PerfCntrGlobalCtl` (PerfMonV2).
pub const AMD_MSR_PERF_GLOBAL_CTL: u32 = 0xC000_0301;
/// AMD core counters without PerfCtrExtCore: `PerfEvtSel0`.
pub const AMD_MSR_LEGACY_EVTSEL0: u32 = 0xC001_0000;
/// AMD core counters without PerfCtrExtCore: `PerfCtr0`.
pub const AMD_MSR_LEGACY_CTR0: u32 = 0xC001_0004;
/// AMD `PerfEvtSel0` with PerfCtrExtCore; counter `n` is `+ 2n`, its
/// `PerfCtr` is the next MSR (`0xC0010201`).
pub const AMD_MSR_EXT_EVTSEL0: u32 = 0xC001_0200;

/// `rdpmc` index flag: a fixed-function counter (Intel).
pub const X86_RDPMC_FIXED: u32 = 1 << 30;

/// Intel architectural event: branch instructions retired that were
/// mispredicted (BR_MISP_RETIRED.ALL_BRANCHES, event 0xC5, umask 0).
pub const INTEL_EV_BR_MISS: u64 = 0x00C5;
/// AMD event select: retired mispredicted branch instructions (0xC3).
pub const AMD_EV_BR_MISS: u64 = 0xC3;
/// AMD event select: CpuClkUnhalted (cycles not in halt).
pub const AMD_EV_CYCLES: u64 = 0x76;
/// AMD event select: RetiredInstructions.
pub const AMD_EV_INSTR: u64 = 0xC0;

/// `PERFEVTSEL` control bits: count in ring 3, count in ring 0, enable.
pub const X86_EVTSEL_USR: u64 = 1 << 16;
pub const X86_EVTSEL_OS: u64 = 1 << 17;
pub const X86_EVTSEL_EN: u64 = 1 << 22;

/// The register value that counts event `sel` in both rings: the event/unit
/// mask image with USR, OS and EN set, and the control bits of `sel`
/// (which has none of its own) cleared.
pub const fn x86_evtsel(sel: u64) -> u64 {
    // sel: event [7:0], unit mask [15:8], AMD event high bits [35:32].
    let image = sel & (0xFFFF | (0xF << 32));
    image | X86_EVTSEL_USR | X86_EVTSEL_OS | X86_EVTSEL_EN
}

/// `IA32_FIXED_CTR_CTRL` with the fixed counters in `fixed` (bit n: counter
/// n) counting in both rings, the other counters' fields as in `cur`.
pub const fn x86_fixed_ctrl(cur: u64, fixed: u8) -> u64 {
    let mut v = cur;
    let mut n = 0;
    while n < 3 {
        if fixed & (1 << n) != 0 {
            // bit 0 OS, bit 1 USR; AnyThread (2) and PMI (3) stay clear.
            v = (v & !(0xF << (4 * n))) | (0b11 << (4 * n));
        }
        n += 1;
    }
    v
}

/// `IA32_PERF_GLOBAL_CTRL` bits of the fixed counters in `fixed`, then the
/// programmable counters in `pmc`.
pub const fn x86_global_ctrl(cur: u64, fixed: u8, pmc: u8) -> u64 {
    cur | ((fixed as u64 & 0x7) << 32) | pmc as u64
}

/// CPUID leaf 0xA of an Intel CPU (architectural performance monitoring).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IntelPmu {
    /// Architectural PMU version (EAX\[7:0\]); 0: none (a hypervisor that
    /// hides it reports 0).
    pub version: u8,
    /// General-purpose counters per logical CPU (EAX\[15:8\]).
    pub gp: u8,
    /// Their width in bits (EAX\[23:16\]).
    pub gp_bits: u8,
    /// Fixed-function counters (EDX\[4:0\]); counter 0 is INST_RETIRED.ANY,
    /// 1 CPU_CLK_UNHALTED.THREAD, 2 CPU_CLK_UNHALTED.REF_TSC. 0 below version 2.
    pub fixed: u8,
    /// Their width in bits (EDX\[12:5\]).
    pub fixed_bits: u8,
}

/// Decode CPUID.0AH (`eax`, `edx`; `ebx` and `ecx` only mark architectural
/// events and fixed-counter bitmaps this kernel does not need).
pub const fn intel_decode(eax: u32, edx: u32) -> IntelPmu {
    let version = (eax & 0xFF) as u8;
    IntelPmu {
        version,
        gp: ((eax >> 8) & 0xFF) as u8,
        gp_bits: ((eax >> 16) & 0xFF) as u8,
        // Fixed counters exist from version 2.
        fixed: if version >= 2 { (edx & 0x1F) as u8 } else { 0 },
        fixed_bits: if version >= 2 { ((edx >> 5) & 0xFF) as u8 } else { 0 },
    }
}

/// How the AMD core counters are reached.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AmdPmu {
    /// Counters (`rdpmc` indices `0..counters`); 0: none.
    pub counters: u8,
    /// MSR of `PerfEvtSel0`.
    pub evtsel0: u32,
    /// MSR of `PerfCtr0`.
    pub ctr0: u32,
    /// MSR distance between counter `n` and `n + 1` (both the select and
    /// the count registers): 2 with PerfCtrExtCore (`evtsel, ctr` pairs),
    /// 1 for the legacy four.
    pub stride: u32,
    /// PerfMonV2: `PerfCntrGlobalCtl` gates the counters.
    pub global_ctl: bool,
}

impl AmdPmu {
    pub const NONE: AmdPmu = AmdPmu { counters: 0, evtsel0: 0, ctr0: 0, stride: 1, global_ctl: false };
}

/// The AMD counters from CPUID: `ext_core` is `0x80000001` ECX\[23\]
/// (PerfCtrExtCore), `v2_eax`/`v2_ebx` are `0x80000022` EAX and EBX (0 when
/// the leaf is absent), `hypervisor` is `CPUID.1` ECX\[31\].
///
/// The six extended counters are the answer wherever ExtCore is set
/// (PerfMonV2 reports the real number, EBX\[3:0\]). The four legacy counters
/// (AMD families before Bulldozer) have no CPUID bit: they are assumed only
/// on bare metal, because a hypervisor that does not enumerate a PMU
/// answers an unknown MSR with #GP.
pub const fn amd_decode(ext_core: bool, v2_eax: u32, v2_ebx: u32, hypervisor: bool) -> AmdPmu {
    if ext_core {
        let v2 = v2_eax & 1 != 0;
        let n = if v2 { (v2_ebx & 0xF) as u8 } else { 6 };
        AmdPmu {
            counters: if n == 0 { 6 } else { n },
            evtsel0: AMD_MSR_EXT_EVTSEL0,
            ctr0: AMD_MSR_EXT_EVTSEL0 + 1,
            stride: 2,
            global_ctl: v2,
        }
    } else if !hypervisor {
        AmdPmu { counters: 4, evtsel0: AMD_MSR_LEGACY_EVTSEL0, ctr0: AMD_MSR_LEGACY_CTR0, stride: 1, global_ctl: false }
    } else {
        AmdPmu::NONE
    }
}

impl AmdPmu {
    /// `PerfEvtSel` MSR of counter `n`.
    pub const fn evtsel(&self, n: u8) -> u32 {
        self.evtsel0 + self.stride * n as u32
    }

    /// `PerfCtr` MSR of counter `n`.
    pub const fn ctr(&self, n: u8) -> u32 {
        self.ctr0 + self.stride * n as u32
    }
}

/// The x86_64 plan: which counters serve cycles, instructions and events,
/// and how ring 0 and ring 3 reach them. Pure: the ISA crate fills it from
/// CPUID, programs the MSRs it names and reads the counters with `rdpmc`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct X86Plan {
    /// Cycle counter: `rdpmc` index, or `None` (the TSC stands in).
    pub cycle_idx: Option<u32>,
    /// Instruction counter `rdpmc` index.
    pub instr_idx: Option<u32>,
    /// Event counter `rdpmc` index.
    pub event_idx: Option<u32>,
    /// Counter width in bits for the cycle, instruction and event counters.
    pub cycle_bits: u8,
    pub instr_bits: u8,
    pub event_bits: u8,
    /// The fixed counters the plan uses (`IA32_FIXED_CTR_CTRL` mask), Intel.
    pub fixed_mask: u8,
    /// The programmable counters it programs for cycles/instructions (AMD:
    /// counters 0 and 1), as a bit mask.
    pub pmc_mask: u8,
    /// AMD: the registers (`Some`); Intel: `None`.
    pub amd: Option<AmdPmu>,
    /// Ring 3 reads the fixed counters (Intel indices) rather than counters
    /// 0 and 1: the vDSO hwcap `PMU_FIXED` bit.
    pub fixed: bool,
    /// A global enable register gates the counters (Intel version 2 or
    /// later `IA32_PERF_GLOBAL_CTRL`, AMD PerfMonV2 `PerfCntrGlobalCtl`).
    pub global: bool,
}

impl X86Plan {
    pub const NONE: X86Plan = X86Plan {
        cycle_idx: None,
        instr_idx: None,
        event_idx: None,
        cycle_bits: 64,
        instr_bits: 64,
        event_bits: 64,
        fixed_mask: 0,
        pmc_mask: 0,
        amd: None,
        fixed: false,
        global: false,
    };
}

/// The Intel plan: fixed counter 0 for instructions and 1 for cycles
/// (version 2 or later), programmable counter 0 for [`Pmu::event`].
pub const fn x86_plan_intel(p: IntelPmu) -> X86Plan {
    let mut plan = X86Plan::NONE;
    if p.version >= 2 && p.fixed >= 1 {
        plan.instr_idx = Some(X86_RDPMC_FIXED);
        plan.instr_bits = p.fixed_bits;
        plan.fixed_mask |= 1;
    }
    if p.version >= 2 && p.fixed >= 2 {
        plan.cycle_idx = Some(X86_RDPMC_FIXED | 1);
        plan.cycle_bits = p.fixed_bits;
        plan.fixed_mask |= 2;
    }
    if p.version >= 1 && p.gp >= 1 {
        plan.event_idx = Some(0);
        plan.event_bits = p.gp_bits;
        plan.pmc_mask = 1;
    }
    plan.fixed = true;
    plan.global = p.version >= 2;
    plan
}

/// The AMD plan: counter 0 counts cycles (event 0x76), 1 instructions
/// (0xC0), 2 serves [`Pmu::event`]; counters are 48 bits.
pub const fn x86_plan_amd(a: AmdPmu) -> X86Plan {
    let mut plan = X86Plan::NONE;
    if a.counters >= 2 {
        plan.cycle_idx = Some(0);
        plan.instr_idx = Some(1);
        plan.cycle_bits = 48;
        plan.instr_bits = 48;
        plan.pmc_mask = 0b11;
    }
    if a.counters >= 3 {
        plan.event_idx = Some(2);
        plan.event_bits = 48;
        plan.pmc_mask = 0b111;
    }
    plan.amd = Some(a);
    plan.global = a.global_ctl;
    plan
}

/// Who made the CPU, as far as the PMU cares.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum X86Vendor {
    Intel,
    /// AMD and Hygon (Zen derivative): the same core counters.
    Amd,
    Other,
}

/// The vendor from CPUID.0 `ebx`, `ecx`, `edx` (the twelve-byte string).
pub const fn x86_vendor(ebx: u32, ecx: u32, edx: u32) -> X86Vendor {
    match (ebx, edx, ecx) {
        // "GenuineIntel"
        (0x756E_6547, 0x4965_6E69, 0x6C65_746E) => X86Vendor::Intel,
        // "AuthenticAMD"
        (0x6874_7541, 0x6974_6E65, 0x444D_4163) => X86Vendor::Amd,
        // "HygonGenuine"
        (0x6F67_7948, 0x6E65_476E, 0x656E_6975) => X86Vendor::Amd,
        _ => X86Vendor::Other,
    }
}

/// The x86_64 plan from CPUID alone, `cpuid(leaf, subleaf)` returning
/// `(eax, ebx, ecx, edx)`. No MSR is named before this says the counters
/// exist, so a CPU or an emulator without them is never touched.
pub fn x86_plan(cpuid: impl Fn(u32, u32) -> (u32, u32, u32, u32)) -> X86Plan {
    let (max, ebx, ecx, edx) = cpuid(0, 0);
    let hypervisor = max >= 1 && cpuid(1, 0).2 >> 31 & 1 != 0;
    match x86_vendor(ebx, ecx, edx) {
        X86Vendor::Intel if max >= 0xA => {
            let (eax, _, _, edx) = cpuid(0xA, 0);
            x86_plan_intel(intel_decode(eax, edx))
        }
        X86Vendor::Amd => {
            let ext_max = cpuid(0x8000_0000, 0).0;
            let ext_core = ext_max >= 0x8000_0001 && cpuid(0x8000_0001, 0).2 >> 23 & 1 != 0;
            let (v2_eax, v2_ebx, _, _) = if ext_max >= 0x8000_0022 { cpuid(0x8000_0022, 0) } else { (0, 0, 0, 0) };
            x86_plan_amd(amd_decode(ext_core, v2_eax, v2_ebx, hypervisor))
        }
        _ => X86Plan::NONE,
    }
}

/// `CR4.PCE`: `rdpmc` from ring 3.
pub const X86_CR4_PCE: u64 = 1 << 8;

// ── riscv64 ─────────────────────────────────────────────────────────────

/// SBI Performance Monitoring Unit extension id ("PMU").
pub const SBI_EXT_PMU: usize = 0x0050_4D55;
/// Function ids of the extension.
pub const SBI_PMU_NUM_COUNTERS: usize = 0;
pub const SBI_PMU_COUNTER_GET_INFO: usize = 1;
pub const SBI_PMU_COUNTER_CONFIG_MATCHING: usize = 2;
pub const SBI_PMU_COUNTER_START: usize = 3;
pub const SBI_PMU_COUNTER_STOP: usize = 4;

/// `counter_config_matching` flags: clear the counter and start it.
pub const SBI_PMU_CFG_CLEAR_AND_START: usize = (1 << 1) | (1 << 2);

/// SBI hardware general event `code` as an event index (type 0).
pub const fn sbi_hw_event(code: u16) -> u64 {
    code as u64
}
/// SBI hardware general events.
pub const SBI_HW_BRANCH_MISSES: u64 = sbi_hw_event(6);
pub const SBI_HW_CACHE_MISSES: u64 = sbi_hw_event(4);

/// A hardware counter `counter_get_info` described.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RvCounter {
    /// CSR number (`hpmcounter3` is 0xC03).
    pub csr: u16,
    /// Width in bits.
    pub bits: u8,
}

/// Decode a `counter_get_info` value (`xlen` = 64): bit 63 set is a firmware
/// counter (not readable as a CSR); else CSR \[11:0\] and width-1 \[17:12\].
/// `None` for a firmware counter, or a CSR outside `hpmcounter3..=31`.
pub const fn rv_counter_info(value: u64, xlen: u8) -> Option<RvCounter> {
    if (value >> (xlen as u32 - 1)) & 1 != 0 {
        return None;
    }
    let csr = (value & 0xFFF) as u16;
    if csr < 0xC03 || csr > 0xC1F {
        return None;
    }
    Some(RvCounter { csr, bits: (((value >> 12) & 0x3F) + 1) as u8 })
}

/// The counter-index mask of `hpmcounter3..` for a `num` counter PMU (bit n
/// is counter index n; indices 0..=2 are cycle, time, instret and never
/// programmable). 0 when `num <= 3`.
pub const fn rv_programmable_mask(num: usize) -> usize {
    if num <= 3 { return 0; }
    let n = if num > 32 { 32 } else { num };
    (((1u64 << n) - 1) as usize) & !0b111
}

/// The first hardware counter `info(idx)` (the `counter_get_info` value of
/// counter `idx`) describes among the programmable ones of a `num` counter
/// PMU: its index and CSR. `None`: the firmware has no hardware counter to
/// give (all firmware counters, or `num` covers only cycle/time/instret).
pub fn rv_first_hw_counter(num: usize, mut info: impl FnMut(usize) -> u64) -> Option<(usize, RvCounter)> {
    let mask = rv_programmable_mask(num);
    let mut idx = 3;
    while idx < 32 {
        if mask >> idx & 1 != 0 {
            if let Some(c) = rv_counter_info(info(idx), 64) {
                return Some((idx, c));
            }
        }
        idx += 1;
    }
    None
}

/// `scounteren` for ring 3: TM (the clock) always; CY and IR only as asked.
pub const fn rv_scounteren(user_cycles: bool, user_instructions: bool) -> usize {
    const CY: usize = 1 << 0;
    const TM: usize = 1 << 1;
    const IR: usize = 1 << 2;
    TM | if user_cycles { CY } else { 0 } | if user_instructions { IR } else { 0 }
}

// ── aarch64 ─────────────────────────────────────────────────────────────

/// `PMCR_EL0.E`: all counters enabled.
pub const A64_PMCR_E: u64 = 1 << 0;
/// `PMCR_EL0.D`: the cycle counter counts every 64th cycle.
pub const A64_PMCR_D: u64 = 1 << 3;
/// `PMCR_EL0.LP`: event counters overflow at 64 bits (PMUv3p5).
pub const A64_PMCR_LP: u64 = 1 << 7;
/// `PMCNTENSET_EL0.C`: the cycle counter.
pub const A64_PMCNTEN_C: u64 = 1 << 31;
/// Architected event: instruction architecturally executed.
pub const A64_EV_INST_RETIRED: u64 = 0x08;
/// Architected event: branch mispredicted or not predicted.
pub const A64_EV_BR_MIS_PRED: u64 = 0x10;
/// Architected event: level 1 data cache refill.
pub const A64_EV_L1D_CACHE_REFILL: u64 = 0x03;
/// `PMUSERENR_EL0`: CR (EL0 may read the cycle counter) and ER (EL0 may read
/// the event counters). With EN clear these two let EL0 READ and nothing
/// else; EN would also let EL0 write PMCR_EL0, PMCNTENSET/CLR_EL0,
/// PMOVSCLR_EL0, PMSELR_EL0, PMXEVTYPER_EL0, PMEVTYPERn_EL0 and PMCCFILTR_EL0,
/// that is stop, reset or retarget the counters the kernel's own `Pmu` users
/// (wcet, lockdep hold times) depend on. EN is therefore never set
/// ([`a64_pmuserenr`]), as in Linux's user-space counter access.
pub const A64_PMUSERENR_CR: u64 = 1 << 2;
pub const A64_PMUSERENR_ER: u64 = 1 << 3;

/// `PMCR_EL0.N`: the number of event counters.
pub const fn a64_pmcr_n(pmcr: u64) -> u8 {
    ((pmcr >> 11) & 0x1F) as u8
}

/// `PMCR_EL0` with the counters on, the cycle counter undivided and, when
/// the PMU is v3p5 (`pmuver >= 6`), the event counters 64 bits wide; every
/// other bit as read.
pub const fn a64_pmcr(pmcr: u64, pmuver: u8) -> u64 {
    let v = (pmcr | A64_PMCR_E) & !A64_PMCR_D;
    if pmuver >= 6 { v | A64_PMCR_LP } else { v }
}

/// Width of an event counter: 64 with `LP`, else 32.
pub const fn a64_event_bits(pmuver: u8) -> u8 {
    if pmuver >= 6 { 64 } else { 32 }
}

/// `PMUSERENR_EL0` for ring 3: the read bits asked for, never EN (EN opens
/// the control registers to writes, see [`A64_PMUSERENR_CR`]). The user
/// instruction count is event counter 0; ER also lets ring 3 read counter 1
/// ([`Pmu::event`]), a read-only view.
pub const fn a64_pmuserenr(user_cycles: bool, user_instructions: bool) -> u64 {
    (if user_cycles { A64_PMUSERENR_CR } else { 0 }) | if user_instructions { A64_PMUSERENR_ER } else { 0 }
}

/// `PMCNTENSET_EL0` for the plan: the cycle counter, event counter 0
/// (instructions) when the PMU has one, and counter 1 for [`Pmu::event`]
/// when it has two.
pub const fn a64_cnten(n: u8) -> u64 {
    A64_PMCNTEN_C | if n >= 1 { 1 } else { 0 } | if n >= 2 { 2 } else { 0 }
}

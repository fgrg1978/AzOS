// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-CPU identity + low-level idle on ARMv8-A: the hart id, `wfi`, the tick
//! counter, and the MIDR_EL1 (CPU model) and MPIDR_EL1 (topology) decoders.

/// ARMv8.5 feature detection from the architectural ID registers.
pub mod features;

/// Hardware control-flow integrity: the pointer-authentication key and `EnIA`.
pub mod cfi;

use core::sync::atomic::{AtomicU64, Ordering};

/// Read `TPIDR_EL1` and return this PE's logical hart index.
///
/// U10-4 (audit): this used to decode `MPIDR_EL1` directly
/// (`Aff0 | Aff1 << 8 | Aff2 << 16`), a SECOND hart-identity source
/// disagreeing with the one the scheduler actually indexes by —
/// `crates/core/sched/src/smp.rs::current_cpu_id()` reads `TPIDR_EL1`, the
/// logical id `boot.S` publishes (`msr TPIDR_EL1, x20`, both the primary
/// and secondary paths, before any Rust runs — see `entry/aarch64/asm/
/// boot.S`). On QEMU virt's flat `-smp N` the two values coincide (Aff1/
/// Aff2 are 0, so the MPIDR decode happens to equal the logical index),
/// which hid the divergence; on any topology with Aff1 != 0 the old decode
/// returned a value >= 256, and every caller keying a fixed-size per-hart
/// table by `hart_id()` — `crates/core/sync::preempt::slot()` (`SLOTS = 8`),
/// `domains/robot/safety-core::txn`/`watchdog`, `crates/core/ipc::fast_ipc`/`trace`,
/// `crates/core/syscall::dispatch`, `kernel::panic` — silently fell outside the
/// table's range on that hart (`preempt::slot()` returns `None`, i.e.
/// preemption control OFF; the others index out of range or misfile the
/// diagnostic).
///
/// Reading `TPIDR_EL1` here instead makes this crate's `hart_id()` and
/// `crates/core/sched`'s `current_cpu_id()` the SAME read of the SAME register —
/// one hart-identity source on this ISA, matching riscv64 (`tp`, read by
/// both). The raw `MPIDR_EL1` decode is still available, for topology
/// purposes only, via [`read_mpidr`].
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn hart_id() -> usize {
    let id: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, TPIDR_EL1",
            out(reg) id,
            options(nomem, nostack, preserves_flags),
        );
    }
    id as usize
}

/// Wait For Interrupt — low-power idle. Maps directly to the ARM
/// `WFI` instruction.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn wfi() {
    unsafe {
        core::arch::asm!(
            "wfi",
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Read the monotonic tick counter — `CNTVCT_EL0`, the generic timer's
/// virtual count register.
///
/// Free-function twin of `Cpu::now_ticks`, matching `arch-riscv64`'s `cpu`
/// module so the `azos_arch` facade exposes the same name on both ISAs.
/// Same timebase `set_timer_deadline` writes `CNTV_CVAL_EL0` against.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn now_ticks() -> u64 {
    crate::sysregs::read_cntvct_el0()
}

/// Read the generic timer's live counter frequency (`CNTFRQ_EL0`), set by
/// firmware at boot. Lets a boot path cross-check a compile-time constant
/// (`azos_drv_base::platform::hw::TIMER_FREQ`) against the real
/// register, the same role `kernel/src/main.rs` already gives the RISC-V
/// `TIMER_FREQ` vs the parsed DTB on that ISA.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn timer_freq_hw() -> u64 {
    crate::sysregs::read_cntfrq_el0()
}

// ── MIDR_EL1: the CPU model ──────────────────────────────────────────────
//
// MIDR_EL1 — Main ID Register — implementer / part-number /
// revision decoder. Mirror of `arch-x86_64::cpuid`.
//
// Used by boot log + procfs to identify the CPU model and gate
// per-core errata workarounds.

/// Decoded MIDR_EL1.
#[derive(Clone, Copy, Debug)]
pub struct Midr {
    pub raw:         u64,
    pub implementer: u8,
    pub variant:     u8,
    pub architecture:u8,
    pub part_num:    u16,
    pub revision:    u8,
}

impl Midr {
    /// JEP106 implementer codes — the common ones a robotics
    /// kernel will actually see. Codes are 7-bit; bit 7 is the
    /// continuation flag (ignored here).
    pub const IMPL_ARM:       u8 = 0x41; // 'A'
    pub const IMPL_BROADCOM:  u8 = 0x42;
    pub const IMPL_CAVIUM:    u8 = 0x43;
    pub const IMPL_DEC:       u8 = 0x44;
    pub const IMPL_FUJITSU:   u8 = 0x46;
    pub const IMPL_INFINEON:  u8 = 0x49;
    pub const IMPL_MOTOROLA:  u8 = 0x4D;
    pub const IMPL_NVIDIA:    u8 = 0x4E;
    pub const IMPL_APM:       u8 = 0x50;
    pub const IMPL_QUALCOMM:  u8 = 0x51;
    pub const IMPL_MARVELL:   u8 = 0x56;
    pub const IMPL_INTEL:     u8 = 0x69;
    pub const IMPL_AMPERE:    u8 = 0xC0;
    pub const IMPL_APPLE:     u8 = 0x61;

    /// ARM Limited part numbers. The kernel uses these to gate
    /// per-µarch quirks (e.g. cortex-a72 erratum 832075).
    pub const PART_CORTEX_A53:    u16 = 0xD03;
    pub const PART_CORTEX_A57:    u16 = 0xD07;
    pub const PART_CORTEX_A72:    u16 = 0xD08; // QEMU virt default
    pub const PART_CORTEX_A73:    u16 = 0xD09;
    pub const PART_CORTEX_A55:    u16 = 0xD05;
    pub const PART_CORTEX_A75:    u16 = 0xD0A;
    pub const PART_CORTEX_A76:    u16 = 0xD0B;
    pub const PART_CORTEX_A78:    u16 = 0xD41;
    pub const PART_NEOVERSE_N1:   u16 = 0xD0C;
    pub const PART_NEOVERSE_V1:   u16 = 0xD40;
    pub const PART_NEOVERSE_N2:   u16 = 0xD49;

    pub fn implementer_name(&self) -> &'static str {
        match self.implementer {
            Self::IMPL_ARM      => "ARM",
            Self::IMPL_BROADCOM => "Broadcom",
            Self::IMPL_CAVIUM   => "Cavium",
            Self::IMPL_FUJITSU  => "Fujitsu",
            Self::IMPL_NVIDIA   => "NVIDIA",
            Self::IMPL_APM      => "Applied Micro",
            Self::IMPL_QUALCOMM => "Qualcomm",
            Self::IMPL_MARVELL  => "Marvell",
            Self::IMPL_INTEL    => "Intel",
            Self::IMPL_AMPERE   => "Ampere",
            Self::IMPL_APPLE    => "Apple",
            _                   => "Unknown",
        }
    }

    /// Best-effort part-name lookup for ARM-implemented cores.
    /// Non-ARM implementers reuse the part-num field for their
    /// own product lines so this only resolves names when
    /// `implementer == IMPL_ARM`.
    pub fn part_name(&self) -> &'static str {
        if self.implementer != Self::IMPL_ARM {
            return "non-ARM impl";
        }
        match self.part_num {
            Self::PART_CORTEX_A53    => "Cortex-A53",
            Self::PART_CORTEX_A55    => "Cortex-A55",
            Self::PART_CORTEX_A57    => "Cortex-A57",
            Self::PART_CORTEX_A72    => "Cortex-A72",
            Self::PART_CORTEX_A73    => "Cortex-A73",
            Self::PART_CORTEX_A75    => "Cortex-A75",
            Self::PART_CORTEX_A76    => "Cortex-A76",
            Self::PART_CORTEX_A78    => "Cortex-A78",
            Self::PART_NEOVERSE_N1   => "Neoverse-N1",
            Self::PART_NEOVERSE_V1   => "Neoverse-V1",
            Self::PART_NEOVERSE_N2   => "Neoverse-N2",
            _                        => "Unknown ARM core",
        }
    }
}

/// Read MIDR_EL1 and decode.
#[cfg(target_arch = "aarch64")]
pub fn read_midr() -> Midr {
    let raw: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, MIDR_EL1",
            out(reg) raw,
            options(nomem, nostack, preserves_flags),
        );
    }
    Midr {
        raw,
        implementer:  ((raw >> 24) & 0xFF) as u8,
        variant:      ((raw >> 20) & 0xF)  as u8,
        architecture: ((raw >> 16) & 0xF)  as u8,
        part_num:     ((raw >> 4)  & 0xFFF) as u16,
        revision:     ( raw        & 0xF)  as u8,
    }
}

/// Read REVIDR_EL1 — implementer-defined revision details. The
/// kernel uses it as part of erratum-matching tuples (impl, part,
/// variant, revision, revidr) for per-silicon-revision quirks.
#[cfg(target_arch = "aarch64")]
pub fn read_revidr() -> u64 {
    let raw: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, REVIDR_EL1",
            out(reg) raw,
            options(nomem, nostack, preserves_flags),
        );
    }
    raw
}

// ── Host-build stubs ────────────────────────────────────────

#[cfg(not(target_arch = "aarch64"))]
pub fn read_midr() -> Midr {
    Midr { raw: 0, implementer: 0, variant: 0, architecture: 0,
           part_num: 0, revision: 0 }
}
#[cfg(not(target_arch = "aarch64"))]
pub fn read_revidr() -> u64 { 0 }

// ── MPIDR_EL1: this PE in the topology ───────────────────────────────────
//
// MPIDR_EL1 — Multiprocessor Affinity Register decoder.
//
// 64-bit register that identifies *this* PE within the system
// topology. Layout:
//
// bits [7:0]    Aff0 — innermost level (typically thread / SMT)
// bits [15:8]   Aff1 — core within cluster
// bits [23:16]  Aff2 — cluster within socket
// bit  [24]     MT   — 1 if Aff0 is "thread" rather than "PE"
// bits [29:30]  RES0
// bit  [30]     U    — 1 if uniprocessor (no other PEs)
// bit  [31]     RES1 — always 1
// bits [39:32]  Aff3 — outermost (socket / package)
//
// Already used implicitly by `aarch64-hello`: the PSCI CPU_ON
// target argument is "Aff0..3 packed", and the ICC_SGI1R_EL1
// `TargetList` field lives within `Aff0` of a specific Aff1/2/3
// cluster. Until this module landed callers were poking the
// sysreg directly + bit-twiddling on the result.

/// Decoded MPIDR_EL1.
#[derive(Clone, Copy, Debug)]
pub struct Mpidr {
    pub raw: u64,
    /// Innermost affinity level — thread/SMT when `MT == 1`,
    /// PE otherwise.
    pub aff0: u8,
    pub aff1: u8,
    pub aff2: u8,
    pub aff3: u8,
    /// True when Aff0 selects a hardware thread (vs a PE) — set
    /// on big.LITTLE designs with SMT cores.
    pub multi_thread: bool,
    /// True when this is the only PE in the system.
    pub uniprocessor: bool,
}

impl Mpidr {
    /// Build a `target_cpu` argument for PSCI CPU_ON from the
    /// caller's chosen affinity values. Aff0-2 occupy bits
    /// [7:0]/[15:8]/[23:16] and Aff3 jumps to [39:32].
    pub const fn pack_for_psci(aff0: u8, aff1: u8, aff2: u8, aff3: u8) -> u64 {
        (aff0 as u64)
            | ((aff1 as u64) << 8)
            | ((aff2 as u64) << 16)
            | ((aff3 as u64) << 32)
    }

    /// Build an ICC_SGI1R_EL1 value for an SGI targeting the
    /// specific PE matching this MPIDR's Aff1/2/3 cluster.
    /// `intid` is the SGI ID (0..=15).
    ///
    /// Bit layout (ICC_SGI1R_EL1):
    ///   bits [15:0]  TargetList — bit N = PE with Aff0=N
    ///   bits [23:16] Aff1
    ///   bits [27:24] INTID
    ///   bits [39:32] Aff2
    ///   bit  [40]    IRM (1 = all-but-self)
    ///   bits [55:48] Aff3
    ///
    /// **Aff0 must be < 16.** This encoding has no `RS` (Range Selector)
    /// term, so an Aff0 >= 16 silently addresses the wrong PE (its low
    /// nibble, under `RS=0`) instead of the one intended. Every caller in
    /// this tree today has Aff0 < 16 (QEMU virt `-smp 2..4`), which is why
    /// this went unnoticed until [`crate::gic::sgi1r_encode`] added the
    /// `RS` term for the general case — prefer that one for new code;
    /// this method stays for the existing self-targeted call sites.
    pub fn sgi_to_self_aff0(&self, intid: u8) -> u64 {
        let target_list: u64 = 1 << (self.aff0 & 0xF);
        target_list
            | ((self.aff1 as u64) << 16)
            | ((intid as u64 & 0xF) << 24)
            | ((self.aff2 as u64) << 32)
            | ((self.aff3 as u64) << 48)
    }

    /// This PE's affinity packed via [`affinity_key`] — the canonical
    /// `u32` shape [`crate::gic::typer_affinity_key`] and
    /// [`crate::gic::find_redistributor`] use to match a redistributor
    /// frame against an MPIDR without needing the `Mpidr` type itself.
    pub const fn affinity_key(&self) -> u32 {
        affinity_key(self.aff0, self.aff1, self.aff2, self.aff3)
    }
}

/// Pack `Aff0..Aff3` into one `u32`: `Aff3<<24 | Aff2<<16 | Aff1<<8 | Aff0`.
///
/// A free function (not just [`Mpidr::affinity_key`]) so a caller with a
/// raw `GICR_TYPER` value — which carries the SAME four affinity bytes,
/// just at different bit offsets — can pack it into the identical shape
/// via [`crate::gic::typer_affinity_key`] and compare the two with a
/// plain `==`. Neither packer needs the other module's type, which is
/// what lets both be pulled standalone (`#[path]`) into a host test crate
/// without dragging the whole crate graph along.
pub const fn affinity_key(aff0: u8, aff1: u8, aff2: u8, aff3: u8) -> u32 {
    (aff0 as u32) | ((aff1 as u32) << 8) | ((aff2 as u32) << 16) | ((aff3 as u32) << 24)
}

/// Same packing as [`affinity_key`], applied directly to a raw
/// `MPIDR_EL1` value: `Aff0` at bits `[7:0]`, `Aff1` at `[15:8]`, `Aff2`
/// at `[23:16]`, `Aff3` at `[39:32]` — see [`read_mpidr`]'s decode for
/// the same field positions. Bits 24 (MT) and 30 (U) sit BETWEEN Aff2 and
/// Aff3 and must not leak into either field; this pulls each field out by
/// its own mask+shift rather than a single contiguous slice, so they
/// can't.
pub const fn mpidr_affinity_key(raw: u64) -> u32 {
    affinity_key(
        (raw & 0xFF) as u8,
        ((raw >> 8) & 0xFF) as u8,
        ((raw >> 16) & 0xFF) as u8,
        ((raw >> 32) & 0xFF) as u8,
    )
}

/// Read MPIDR_EL1 and decode.
#[cfg(target_arch = "aarch64")]
pub fn read_mpidr() -> Mpidr {
    let raw: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, MPIDR_EL1",
            out(reg) raw,
            options(nomem, nostack, preserves_flags),
        );
    }
    Mpidr {
        raw,
        aff0:        ( raw         & 0xFF) as u8,
        aff1:        ((raw >> 8)   & 0xFF) as u8,
        aff2:        ((raw >> 16)  & 0xFF) as u8,
        aff3:        ((raw >> 32)  & 0xFF) as u8,
        multi_thread: ((raw >> 24) & 1) != 0,
        uniprocessor: ((raw >> 30) & 1) != 0,
    }
}

// ── Host-build stubs ────────────────────────────────────────

#[cfg(not(target_arch = "aarch64"))]
pub fn read_mpidr() -> Mpidr {
    Mpidr {
        raw: 0, aff0: 0, aff1: 0, aff2: 0, aff3: 0,
        multi_thread: false, uniprocessor: false,
    }
}

// ── Which MPIDR each CPU has ────────────────────────────────────────────────
//
// A line is routed to a CPU by its affinity (`GICD_IROUTER`), and a caller
// names the CPU by the kernel's index. Each CPU says what its MPIDR is when
// it comes up; the boot CPU says so from the interrupt routing init.

/// CPUs tracked: the kernel's ceiling (`NR_CPUS`, at most 64).
pub(crate) const CPUS: usize = 64;

/// Raw `MPIDR_EL1` per CPU index, with [`CPU_KNOWN`]'s bit set once written.
static CPU_MPIDR: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];
static CPU_KNOWN: AtomicU64 = AtomicU64::new(0);

/// CPU `cpu` has MPIDR `raw`. Called by the CPU itself as it comes up (the
/// boot CPU in `boot_hooks`, each secondary in `secondary_publish_online`),
/// so it is also where the CPU's FEAT_BBM level is noted
/// ([`features::BbmSurvey`]).
pub fn note_cpu_mpidr(cpu: usize, raw: u64) {
    features::note_this_cpu_bbm(cpu);
    if cpu < CPUS {
        CPU_MPIDR[cpu].store(raw, Ordering::Relaxed);
        CPU_KNOWN.fetch_or(1 << cpu, Ordering::Release);
    }
}

/// The raw `MPIDR_EL1` of CPU `cpu`, `None` for one that has not come up.
pub fn cpu_mpidr(cpu: usize) -> Option<u64> {
    if cpu < CPUS && CPU_KNOWN.load(Ordering::Acquire) & (1 << cpu) != 0 {
        Some(CPU_MPIDR[cpu].load(Ordering::Relaxed))
    } else {
        None
    }
}

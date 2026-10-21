// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Deep idle on x86_64: the C-state ladder `Cpu::cpu_idle(depth)` enters.
//!
//! **Depth.** Depth 0 is `hlt` (C1, the architectural wait, as `wfi` is on the
//! other ISAs). Depth `d >= 1` is the `d`-th state of the [`Ladder`], ordered
//! by exit latency, shallowest first. The energy model's idle list for the
//! domain is `[hlt, ladder[0], ladder[1], ..]`, so the depth the idle
//! governor picks means the same state in the model and here. The kernel's
//! boot builds that list from [`Ladder::model_state`] for every domain the
//! topology declares without an `idle` table, and checks a table the
//! topology does declare against the ladder ([`Ladder::depth_within_claims`]),
//! capping the depth `cpu_idle` enters at the first state it understates
//! ([`cap_depth`]). With no energy model (no topology `[energy.domain.*]`)
//! nothing asks for a depth and `cpu_idle` stays `hlt`.
//!
//! **Where the numbers come from.** x86 has no device-tree `idle-states` and
//! the firmware table that would carry them (ACPI `_CST`) is not read, so the
//! latencies are the per-model tables Linux's `intel_idle` keeps (exit latency
//! and target residency in microseconds, one table per CPU family we target).
//! A model with no table gets NO deep state: a latency is never guessed, because
//! one that is too small lets the governor sleep past a real-time deadline
//! (invariant I3) and one that is too large only wastes a little power.
//!
//! **What may be entered.** A state is on the ladder only if
//!
//! * `MONITOR`/`MWAIT` are usable (`CPUID.1:ECX[3]`) with the extensions
//!   `CPUID.5` enumerates: ECX[0] (the sub-state leaf is valid) and ECX[1]
//!   (an interrupt is a break event with `IF` clear, which the entry relies
//!   on instead of a second `sti`);
//! * `CPUID.5:EDX` lists a sub-state for its hint (as `intel_idle` checks);
//! * if it can stop the local APIC timer or the TSC (every hint above C1/C1E),
//!   the CPU says neither stops: `CPUID.6:EAX[2]` (ARAT) and the invariant
//!   TSC bit. Without them the wake-up armed on this CPU, and the clock
//!   `cpu_idle` reports its sleep with, would be lost in the state.
//!
//! AMD and Hygon have `MONITORX`/`MWAITX` (`CPUID.80000001:ECX[29]`) and no
//! per-model table here: their deeper C-states are entered by ACPI I/O reads
//! (`_CST`), not by a hint, so the ladder is the one `MWAITX` C1 state.
//!
//! Everything but [`enter`] and [`read`] is pure, and the host suite
//! (`tests/host/arch-tests/src/idle_x86.rs`) runs it.

use super::features::{decode_ident, CpuIdent, CpuidLeaves, Vendor};

/// States on a ladder: the energy model holds four per domain, one of which
/// is `hlt`.
pub const MAX_STATES: usize = 3;

/// One state `MWAIT`/`MWAITX` can be asked to enter.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CState {
    /// The vendor's name for it (`C1E`, `C6`, ...), for the boot line.
    pub name: &'static str,
    /// The `MWAIT` hint in EAX: bits 7:4 the target C-state (0 is C1, 1 is
    /// C3 ..), bits 3:0 the sub-state.
    pub hint: u8,
    /// Time from a wake event back to running, microseconds.
    pub exit_latency_us: u32,
    /// The shortest sleep that pays back the entry and exit.
    pub target_residency_us: u32,
}

impl CState {
    const fn new(name: &'static str, hint: u8, exit: u32, residency: u32) -> Self {
        Self { name, hint, exit_latency_us: exit, target_residency_us: residency }
    }

    /// Hints above C1/C1E (bits 7:4 non-zero) may stop the local APIC timer
    /// and the TSC; the C1 family never does.
    pub const fn may_stop_timer(&self) -> bool {
        self.hint >> 4 != 0
    }
}

/// Which instruction pair enters the state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Wait {
    /// `MONITOR`/`MWAIT` (Intel).
    Mwait,
    /// `MONITORX`/`MWAITX` (AMD, Hygon).
    Mwaitx,
}

/// The states this CPU can enter besides `hlt`, shallowest first.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ladder {
    n: u8,
    wait: Wait,
    states: [CState; MAX_STATES],
}

const NO_STATE: CState = CState::new("", 0, 0, 0);

impl Ladder {
    /// Nothing but `hlt`.
    pub const EMPTY: Self = Self { n: 0, wait: Wait::Mwait, states: [NO_STATE; MAX_STATES] };

    /// The states, depth 1 first.
    pub fn states(&self) -> &[CState] {
        &self.states[..self.n as usize]
    }

    /// The instruction pair that enters them.
    pub fn wait(&self) -> Wait {
        self.wait
    }

    /// What the energy model's idle list holds at `depth`: `(name, exit
    /// latency us, target residency us)`. Depth 0 is `hlt`, the one the
    /// governor never bounds by I3; a depth past the ladder is the deepest
    /// state there is (as [`Self::pick`]). The model's list for a domain is
    /// depths `0..=states().len()`.
    pub fn model_state(&self, depth: u8) -> (&'static str, u32, u32) {
        match self.pick(depth) {
            None => ("hlt", 0, 0),
            Some(s) => (s.name, s.exit_latency_us, s.target_residency_us),
        }
    }

    /// The state `cpu_idle(depth)` enters: `None` for `hlt` (depth 0, or no
    /// state at all). A depth past the ladder is entered as the deepest
    /// state there is, so the state entered is never deeper than asked.
    pub fn pick(&self, depth: u8) -> Option<&CState> {
        let n = self.n as usize;
        if depth == 0 || n == 0 {
            return None;
        }
        Some(&self.states[(depth as usize).min(n) - 1])
    }

    /// Whether the energy model's claim for `depth` is smaller than the real
    /// exit latency of the state entered for it: the governor would then keep
    /// a real-time deadline it cannot keep (I3). `hlt` is not checked.
    pub fn understates(&self, depth: u8, model_exit_us: u32) -> bool {
        self.pick(depth).is_some_and(|s| s.exit_latency_us > model_exit_us)
    }

    /// The deepest depth the model can be trusted to: `claims[i]` is the exit
    /// latency the model gives depth `i + 1`; the result stops before the
    /// first depth that [`Self::understates`] its state.
    pub fn depth_within_claims(&self, claims: &[u32]) -> u8 {
        let ok = claims.iter().enumerate().take_while(|(i, c)| !self.understates(*i as u8 + 1, **c)).count();
        ok.min(u8::MAX as usize) as u8
    }
}

// ── Per-model tables ───────────────────────────────────────────────────────
// After Linux `drivers/idle/intel_idle.c` (`*_cstates`): exit latency and
// target residency in microseconds per state, shallow to deep. Each family
// lists the three states worth a depth: C1E, C6 and the deepest package state
// (where there is one); the shallow C1 is `hlt`.

const HSW: &[CState] =
    &[CState::new("C1E", 0x01, 10, 20), CState::new("C6", 0x20, 133, 400), CState::new("C10", 0x60, 2600, 7700)];
const SKL: &[CState] =
    &[CState::new("C1E", 0x01, 10, 20), CState::new("C6", 0x20, 85, 200), CState::new("C10", 0x60, 890, 5000)];
/// Ice Lake client, Tiger Lake, Rocket Lake: C6 costs twice Skylake's.
const ICL: &[CState] = &[CState::new("C1E", 0x01, 4, 4), CState::new("C6", 0x20, 170, 600)];
const SKX: &[CState] = &[CState::new("C1E", 0x01, 10, 20), CState::new("C6", 0x20, 133, 600)];
const ICX: &[CState] = &[CState::new("C1E", 0x01, 4, 4), CState::new("C6", 0x20, 170, 600)];
const SPR: &[CState] = &[CState::new("C1E", 0x01, 2, 4), CState::new("C6", 0x20, 290, 800)];
const ADL: &[CState] =
    &[CState::new("C1E", 0x01, 2, 4), CState::new("C6", 0x20, 220, 600), CState::new("C10", 0x60, 680, 2000)];
/// AMD, Hygon: `MWAITX` hint 0 is C1. Same depth as `hlt` in power, but the
/// wake can be a store to the monitored line.
const AMD: &[CState] = &[CState::new("C1", 0x00, 1, 2)];

/// The table for an Intel family-6 display model (`intel-family.h`), `None`
/// for a model with no table.
fn intel_table(model: u16) -> Option<&'static [CState]> {
    Some(match model {
        // Haswell, Haswell-L, Haswell-G, Broadwell, Broadwell-G.
        0x3C | 0x45 | 0x46 | 0x3D | 0x47 => HSW,
        // Skylake-L/-S, Kaby Lake-L/-S, Comet Lake-S/-L.
        0x4E | 0x5E | 0x8E | 0x9E | 0xA5 | 0xA6 => SKL,
        // Ice Lake-L, Tiger Lake-L/-S, Rocket Lake.
        0x7E | 0x8C | 0x8D | 0xA7 => ICL,
        // Skylake-X, Cascade Lake, Cooper Lake.
        0x55 => SKX,
        // Ice Lake-X, Ice Lake-D.
        0x6A | 0x6C => ICX,
        // Sapphire Rapids, Emerald Rapids.
        0x8F | 0xCF => SPR,
        // Alder Lake-S/-P, Raptor Lake-S/-P/-B.
        0x97 | 0x9A | 0xB7 | 0xBA | 0xBF => ADL,
        _ => return None,
    })
}

/// The table for a CPU, `None` where none is known.
pub fn table_for(id: &CpuIdent) -> Option<&'static [CState]> {
    match id.vendor {
        Vendor::Intel if id.family == 6 => intel_table(id.model),
        Vendor::Amd | Vendor::Hygon => Some(AMD),
        _ => None,
    }
}

// ── What CPUID says ────────────────────────────────────────────────────────

/// The CPUID words the ladder is built from: the shared decode plus the two
/// leaves only idle reads.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct IdleCpuid {
    /// Vendor, family/model, `MONITOR`, `MONITORX`, the invariant TSC bit.
    pub base: CpuidLeaves,
    /// CPUID.5:ECX — bit 0 extensions enumerated, bit 1 interrupts break
    /// `MWAIT` with `IF` clear.
    pub l5_ecx: u32,
    /// CPUID.5:EDX — sub-state count per C-state, a nibble each.
    pub l5_edx: u32,
    /// CPUID.6:EAX — bit 2 is ARAT, the local APIC timer that never stops.
    pub l6_eax: u32,
}

const L1_ECX_MONITOR: u32 = 1 << 3;
const E1_ECX_MONITORX: u32 = 1 << 29;
const E7_EDX_INVARIANT_TSC: u32 = 1 << 8;
const L5_ECX_EXTENSIONS: u32 = 1 << 0;
const L5_ECX_IRQ_BREAK: u32 = 1 << 1;
const L6_EAX_ARAT: u32 = 1 << 2;

/// The sub-states CPUID.5:EDX lists for `hint`'s C-state (nibble `c + 1` of
/// EDX for the hint's bits 7:4 `c`; nibble 0 is C0).
const fn substates(l5_edx: u32, hint: u8) -> u32 {
    let nibble = (hint >> 4) as u32 + 1;
    if nibble >= 8 {
        return 0;
    }
    (l5_edx >> (nibble * 4)) & 0xF
}

/// The ladder this CPU can enter, from what it reports.
pub fn build(c: &IdleCpuid) -> Ladder {
    let id = decode_ident(&c.base);
    let Some(table) = table_for(&id) else { return Ladder::EMPTY };
    let (wait, usable) = match id.vendor {
        Vendor::Intel => (
            Wait::Mwait,
            c.base.l1_ecx & L1_ECX_MONITOR != 0
                && c.l5_ecx & (L5_ECX_EXTENSIONS | L5_ECX_IRQ_BREAK) == L5_ECX_EXTENSIONS | L5_ECX_IRQ_BREAK,
        ),
        _ => (Wait::Mwaitx, c.base.e1_ecx & E1_ECX_MONITORX != 0),
    };
    if !usable {
        return Ladder::EMPTY;
    }
    // A state past C1/C1E is only safe where neither the APIC timer nor the TSC stops in it.
    let timer_safe = c.l6_eax & L6_EAX_ARAT != 0 && c.base.e7_edx & E7_EDX_INVARIANT_TSC != 0;
    let mut l = Ladder { n: 0, wait, states: [NO_STATE; MAX_STATES] };
    for s in table {
        // AMD's leaf 5 is not read: its one state is C1.
        let listed = wait == Wait::Mwaitx || substates(c.l5_edx, s.hint) != 0;
        if listed && (timer_safe || !s.may_stop_timer()) && (l.n as usize) < MAX_STATES {
            l.states[l.n as usize] = *s;
            l.n += 1;
        }
    }
    l
}

/// Execute `cpuid` for the words [`IdleCpuid`] holds. Zero on a host build
/// (the same rule as [`super::features::read_cpuid`]).
pub fn read() -> IdleCpuid {
    #[allow(unused_mut)]
    let mut r = IdleCpuid { base: super::features::read_cpuid(), ..IdleCpuid::default() };
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        use core::arch::x86_64::__cpuid_count;
        let max = __cpuid_count(0, 0).eax;
        if max >= 5 {
            let l5 = __cpuid_count(5, 0);
            (r.l5_ecx, r.l5_edx) = (l5.ecx, l5.edx);
        }
        if max >= 6 {
            r.l6_eax = __cpuid_count(6, 0).eax;
        }
    }
    r
}

// ── The boot CPU's ladder, once ────────────────────────────────────────────

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};

struct Installed {
    /// 0 unprobed, 1 being probed, 2 ready.
    state: AtomicU8,
    ladder: UnsafeCell<Ladder>,
}

// SAFETY: `ladder` is written once, by the CPU that moves `state` 0 -> 1, and
// read only after `state` is 2 (Release store, Acquire load).
unsafe impl Sync for Installed {}

static INSTALLED: Installed = Installed { state: AtomicU8::new(0), ladder: UnsafeCell::new(Ladder::EMPTY) };

/// The deepest depth `cpu_idle` may enter. The boot lowers it
/// ([`cap_depth`]) to what the energy model's latencies can be trusted to, so
/// the idle governor, which bounds its choice by the model's claim against a
/// real-time deadline (I3), never gets a state slower than the claim.
static DEPTH_CAP: AtomicU8 = AtomicU8::new(u8::MAX);

/// Lower the deepest depth `cpu_idle` enters to at most `depth` (0: `hlt`
/// only). Never raises it.
pub fn cap_depth(depth: u8) {
    DEPTH_CAP.fetch_min(depth, Ordering::Relaxed);
}

/// The depth cap ([`u8::MAX`] until the boot lowers it).
pub fn depth_cap() -> u8 {
    DEPTH_CAP.load(Ordering::Relaxed)
}

/// This machine's ladder, probed on first use (by the boot's report or the
/// first idle). One ladder for every CPU: the CPUs of one package report the
/// same C-states.
pub fn ladder() -> &'static Ladder {
    loop {
        match INSTALLED.state.load(Ordering::Acquire) {
            // SAFETY: state 2 means the single write finished.
            2 => return unsafe { &*INSTALLED.ladder.get() },
            0 => {
                if INSTALLED.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                    // SAFETY: the winner of the 0 -> 1 exchange is the only writer.
                    unsafe { *INSTALLED.ladder.get() = build(&read()) };
                    INSTALLED.state.store(2, Ordering::Release);
                }
            }
            _ => core::hint::spin_loop(),
        }
    }
}

// ── Entering a state ───────────────────────────────────────────────────────

/// Sleep in the state `hint` names until an interrupt, on a CPU whose `IF` is
/// set, and return with `IF` set. `line` is the cache line to monitor: one
/// only this CPU writes, so nothing but an interrupt ends the wait.
///
/// The window between deciding to sleep and sleeping is closed the way
/// Linux's `__sti_mwait` closes it: `cli`, arm the monitor, then `sti; mwait`
/// (the instruction after `sti` runs before an interrupt is taken), and the
/// wait ends at once if one is already pending (ECX[0]).
#[cfg(target_arch = "x86_64")]
pub fn enter(wait: Wait, hint: u8, line: *const u8) {
    let hint = hint as u32;
    // SAFETY: `monitor`/`mwait` (`monitorx`/`mwaitx`) at CPL0 on a CPU the
    // ladder says has them; `cli`/`sti` bracket the arming and `IF` is set
    // again on exit, as the caller had it. No memory is touched.
    unsafe {
        match wait {
            Wait::Mwait => core::arch::asm!(
                "cli", "xor ecx, ecx", "xor edx, edx", "monitor", "mov eax, {h:e}", "mov ecx, 1", "sti", "mwait",
                h = in(reg) hint, inout("rax") line => _, out("ecx") _, out("edx") _,
                options(nostack),
            ),
            Wait::Mwaitx => core::arch::asm!(
                "cli", "xor ecx, ecx", "xor edx, edx", "monitorx", "mov eax, {h:e}", "mov ecx, 1", "sti", "mwaitx",
                h = in(reg) hint, inout("rax") line => _, out("ecx") _, out("edx") _,
                options(nostack),
            ),
        }
    }
}

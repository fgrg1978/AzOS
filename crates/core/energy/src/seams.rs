// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The scheduler's energy seams, enum-dispatched with no `dyn`: the
//! variant set is closed and known at build time, so a call is a `match` the
//! compiler can fold.
//!
//! Stage E0 introduces each seam with **only today's behaviour**:
//!
//! | Seam | Variant | What it does |
//! |---|---|---|
//! | [`Placement`] | `Legacy` | `wake_target_cpu`: the pinned hart, else `find_best_cpu` (IPC co-location under `sched-ipc-affinity`) |
//! | [`Governor`] | `Fixed` | no OPP request: the CPUs stay at the frequency firmware left them |
//! | [`IdleGovernor`] | `ShallowOnly` | `wait_for_interrupt` in the idle task (depth 0 of the arch idle seam) |
//!
//! The selections below are `const`s, so in the default build each seam's
//! `match` has one arm and folds to the code it replaced: the kernel's `.text`
//! is unchanged (measured on both ISAs by the wave-12
//! ENERGY report). Stage E3 adds `Governor::{Schedutil, DeadlineFloor}`, E4
//! `IdleGovernor::Teo`; [`Seams::select`] picks them at boot, under Kconfig
//! `ENERGY`, only when a model is present and the signed topology's mode is
//! not `performance`. The `const`s below stay `TODAY`: they are what a
//! kernel built without `ENERGY` runs.

use crate::governor::{self, Decision};
use crate::model::{EnergyMode, EnergyModel, PerfDomain};

/// Where a woken task is enqueued (`select_cpu(task, waker) -> cpu`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// Today's `wake_target_cpu`: the pinned hart, else the CPU whose
    /// residents least outrank the task (`find_best_cpu`, keeping
    /// `pick_cpu_by_load`'s liveness rule), with the IPC co-location exception.
    Legacy,
}

/// Which OPP a performance domain should run at (`target_opp(domain)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Governor {
    /// Today: no request. The domain keeps the frequency it booted at.
    Fixed,
    /// Stage E3: `max(schedutil, safety floor)` ([`crate::governor`]). Reads
    /// no reservation, so it cannot honour I1; [`Seams::select`] never
    /// chooses it, and it stays as the building block `DeadlineFloor` uses.
    Schedutil,
    /// Stage E3: `max(schedutil, deadline floor, safety floor)` (I1, I6).
    DeadlineFloor,
}

impl Governor {
    /// The OPP `domain` should run at, or `None` to leave the clock alone.
    /// `util` (on [`crate::SCALE`]) is the busy fraction of the domain's
    /// busiest CPU at OPP `cur`; `admitted_ppm` the real-time density
    /// admitted on its most loaded hart; `headroom_pct` the schedutil margin
    /// ([`governor::HEADROOM_PCT`] unless the policy changed it).
    #[inline(always)]
    pub fn target_opp(
        &self,
        domain: &PerfDomain,
        util: u32,
        cur: usize,
        admitted_ppm: u32,
        headroom_pct: u32,
    ) -> Option<Decision> {
        match self {
            Self::Fixed => {
                let _ = (domain, util, cur, admitted_ppm, headroom_pct);
                None
            }
            Self::Schedutil => Some(governor::combine(
                governor::schedutil_opp(domain, util, cur, headroom_pct),
                None,
                governor::safety_floor_opp(domain),
            )),
            Self::DeadlineFloor => Some(governor::combine(
                governor::schedutil_opp(domain, util, cur, headroom_pct),
                Some(governor::deadline_floor_opp(domain, admitted_ppm)),
                governor::safety_floor_opp(domain),
            )),
        }
    }
}

/// What an idle CPU does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdleChoice {
    /// Wait for an interrupt (`wfi` / `hlt`): depth 0.
    Shallow,
    /// The domain's idle state of this index (1 and up; 0 is `Shallow`). Entered
    /// through the arch idle seam, `Cpu::cpu_idle(depth)`; an ISA with no
    /// way to enter that state (no suspend parameter, `local-timer-stop`, or a
    /// power-down state without the kernel's resume entry) enters it as the
    /// deepest state it can below it, else the shallow wait. A state that
    /// loses the CPU's context is never chosen for a CPU with real-time state
    /// ([`crate::idle::allowed`]).
    Deep(u8),
}

impl IdleChoice {
    /// The depth to hand `Cpu::cpu_idle`: 0 for `Shallow`, the state index for
    /// `Deep`.
    #[inline(always)]
    pub const fn depth(self) -> u8 {
        match self {
            Self::Shallow => 0,
            Self::Deep(d) => d,
        }
    }
}

/// How deep an idle CPU sleeps (`select_state(cpu, next_timer) -> state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdleGovernor {
    /// Today: always the shallow wait (`Cpu::wait_for_interrupt`).
    ShallowOnly,
    /// Stage E4: TEO-like ([`crate::idle`]). Needs per-CPU history, which
    /// the kernel keeps (`azos_sched::energy::idle_wait`); the stateless
    /// [`IdleGovernor::select_state`] answers `Shallow` for it.
    Teo,
}

impl IdleGovernor {
    /// The state the calling CPU enters now. Both inputs are asked for
    /// lazily, and only by a governor that needs them, so `ShallowOnly` costs
    /// nothing to ask: `cpu` yields the CPU's index (a register read the
    /// compiler may not drop on its own), `next_timer` the next armed timer
    /// deadline in timebase ticks, `None` if none is armed.
    #[inline(always)]
    pub fn select_state<C, N>(&self, cpu: C, next_timer: N) -> IdleChoice
    where
        C: FnOnce() -> usize,
        N: FnOnce() -> Option<u64>,
    {
        let _ = (cpu, next_timer);
        match self {
            Self::ShallowOnly | Self::Teo => IdleChoice::Shallow,
        }
    }
}

/// One choice per seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seams {
    /// Wake-up placement.
    pub placement: Placement,
    /// Frequency.
    pub governor: Governor,
    /// Idle depth.
    pub idle: IdleGovernor,
}

impl Seams {
    /// Today's behaviour, and what every build runs in stages E0–E2.
    pub const TODAY: Self = Self {
        placement: Placement::Legacy,
        governor: Governor::Fixed,
        idle: IdleGovernor::ShallowOnly,
    };

    /// The seams for a machine with `model` in `mode`. Invariant I4: with no
    /// model this is [`Seams::TODAY`] in every mode, and so it is in
    /// `performance` mode with one. Stage E3/E4 opt-in: `balanced` and
    /// `endurance` (chosen by the signed topology alone, I5) take the
    /// `DeadlineFloor` governor and the TEO-like idle governor. Placement
    /// stays `Legacy` until E5. The two modes do not differ yet.
    pub fn select(model: &EnergyModel, mode: EnergyMode) -> Self {
        if !model.is_present() {
            return Self::TODAY;
        }
        match mode {
            EnergyMode::Performance => Self::TODAY,
            EnergyMode::Balanced | EnergyMode::Endurance => Self {
                placement: Placement::Legacy,
                governor: Governor::DeadlineFloor,
                idle: IdleGovernor::Teo,
            },
        }
    }
}

/// The placement every wake-up goes through (`azos_sched`'s
/// `wake_target_cpu`).
pub const PLACEMENT: Placement = Seams::TODAY.placement;
/// The governor in use.
pub const GOVERNOR: Governor = Seams::TODAY.governor;
/// The idle governor both idle tasks go through.
pub const IDLE_GOVERNOR: IdleGovernor = Seams::TODAY.idle;

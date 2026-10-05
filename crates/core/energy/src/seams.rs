// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The scheduler's energy seams (RFC-0051 §4.3–§4.5), enum-dispatched with no
//! `dyn`, the same trade as `policies::Backend`: the variant set is closed and
//! known at build time, so a call is a `match` the compiler can fold.
//!
//! Stage E0 introduces each seam with **only today's behaviour**:
//!
//! | Seam | Variant | What it does |
//! |---|---|---|
//! | [`Placement`] | `Legacy` | `wake_target_cpu`: the pinned hart, else `find_best_cpu` (IPC co-location under `sched-ipc-affinity`) |
//! | [`Governor`] | `Fixed` | no OPP request: the CPUs stay at the frequency firmware left them |
//! | [`IdleGovernor`] | `WfiOnly` | `wfi` in both idle tasks |
//!
//! The selections below are `const`s, so in the default build each seam's
//! `match` has one arm and folds to the code it replaced: the kernel's `.text`
//! is unchanged (RFC-0051 invariant I4, measured on both ISAs by the wave-12
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
    /// admitted on its most loaded hart.
    #[inline(always)]
    pub fn target_opp(
        &self,
        domain: &PerfDomain,
        util: u32,
        cur: usize,
        admitted_ppm: u32,
    ) -> Option<Decision> {
        match self {
            Self::Fixed => {
                let _ = (domain, util, cur, admitted_ppm);
                None
            }
            Self::Schedutil => Some(governor::combine(
                governor::schedutil_opp(domain, util, cur),
                None,
                governor::safety_floor_opp(domain),
            )),
            Self::DeadlineFloor => Some(governor::combine(
                governor::schedutil_opp(domain, util, cur),
                Some(governor::deadline_floor_opp(domain, admitted_ppm)),
                governor::safety_floor_opp(domain),
            )),
        }
    }
}

/// What an idle CPU does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdleChoice {
    /// Wait for an interrupt (`wfi` on both ISAs).
    Wfi,
    /// The domain's idle state of this index (1 and up; 0 is `Wfi`). No
    /// board has a binding for a state deeper than `wfi` yet (no SBI HSM
    /// `HART_SUSPEND`, no PSCI `CPU_SUSPEND` call), so the kernel enters it
    /// as `wfi` and counts the choice.
    Deep(u8),
}

/// How deep an idle CPU sleeps (`select_state(cpu, next_timer) -> state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdleGovernor {
    /// Today: always `wfi`.
    WfiOnly,
    /// Stage E4: TEO-like ([`crate::idle`]). Needs per-CPU history, which
    /// the kernel keeps (`azos_sched::energy::idle_wait`); the stateless
    /// [`IdleGovernor::select_state`] answers `Wfi` for it.
    Teo,
}

impl IdleGovernor {
    /// The state the calling CPU enters now. Both inputs are asked for
    /// lazily, and only by a governor that needs them, so `WfiOnly` costs
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
            Self::WfiOnly | Self::Teo => IdleChoice::Wfi,
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
        idle: IdleGovernor::WfiOnly,
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

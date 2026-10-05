// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Energy-aware scheduling, RFC-0051 stages E0–E4.
//!
//! `Policy` decides which task runs next on a CPU; this crate holds what
//! decides where a task runs, how fast a CPU runs and how deeply it sleeps.
//! Everything here is pure data and integer arithmetic, so the host suite
//! (`tests/host/energy-tests`) tests the same code the kernel links.
//!
//! * [`util`] — `UtilTracker`: per-task and per-CPU utilisation, integer and
//!   bounded. Two variants, a window (the default) and a PELT-like geometric
//!   decay, chosen by Kconfig `ENERGY_UTIL`.
//! * [`model`] — `EnergyModel`: per performance domain, the operating points
//!   `{freq_khz, capacity, power_mw}` and idle states, its validation and the
//!   source order (signed topology, then DTB, then none).
//! * [`dt`] — the DTB source: `operating-points-v2` and `idle-states` tables
//!   read by `azos_dtb::dtb_energy`, turned into a model.
//! * [`seams`] — `Placement`, `Governor`, `IdleGovernor`: enum-dispatched, no
//!   `dyn`. Today's behaviour (`Legacy`, `Fixed`, `WfiOnly`) unless the
//!   signed topology's mode opts in (`balanced`/`endurance` with a model).
//! * [`governor`] — E3: schedutil, the deadline floor (I1), the WCET floor
//!   (I6). Decisions are recorded; no board has a clock driver to apply them.
//! * [`idle`] — E4: the TEO-like idle state choice (I3).

#![cfg_attr(target_os = "none", no_std)]
#![deny(missing_docs)]

pub mod dt;
pub mod governor;
pub mod idle;
pub mod model;
pub mod seams;
pub mod util;

pub use model::{
    resolve, EnergyMode, EnergyModel, EnergySpec, IdleState, ModelFault, ModelSource, Opp,
    PerfDomain, Resolution,
};
pub use seams::{Governor, IdleChoice, IdleGovernor, Placement, Seams};
pub use util::{UtilState, UtilTracker, SCALE};

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Energy-aware scheduling, stages E0–E4.
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
//!   source order (signed topology, then DTB, then the core types the CPUs
//!   report through CPUID, then none).
//! * [`dt`] — the DTB source: `operating-points-v2` and `idle-states` tables
//!   read by `azos_dtb::dtb_energy`, turned into a model.
//! * [`seams`] — `Placement`, `Governor`, `IdleGovernor`: enum-dispatched, no
//!   `dyn`. Today's behaviour (`Legacy`, `Fixed`, `ShallowOnly`) unless the
//!   signed topology's mode opts in (`balanced`/`endurance` with a model).
//! * [`governor`] — E3: schedutil, the deadline floor (I1), the WCET floor
//!   (I6). Decisions are recorded in the tick; the board's apply step moves
//!   the clock and answers each one ([`opp`]'s assertion).
//! * [`idle`] — E4: the TEO-like idle state choice (I3).
//! * [`opp`] — the OPP actuation seam (`OppActuator`), the per-domain
//!   current-OPP bookkeeping (`Dvfs`) and the governor's apply assertion.
//! * [`assertion`] — system power assertions: who keeps the machine out of
//!   system suspend, why, and until when.
//! * [`thermal`] — thermal zones, trips and cooling by OPP capping, with the
//!   deadline and safety floors above the cap, degrade levels and a record ring.
//! * [`policy`] — the run-time policy: limit-checked setters for the governor,
//!   OPP range, headroom, rate limit and idle depth, with a refusal record.

#![cfg_attr(any(target_os = "none", target_os = "azos"), no_std)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod assertion;
pub mod dt;
pub mod governor;
pub mod idle;
pub mod model;
pub mod opp;
pub mod policy;
pub mod seams;
pub mod thermal;
pub mod util;

pub use model::{
    resolve, EnergyMode, EnergyModel, EnergySpec, IdleState, ModelFault, ModelSource, Opp,
    PerfDomain, Resolution,
};
pub use policy::{Policy, Refusal};
pub use seams::{Governor, IdleChoice, IdleGovernor, Placement, Seams};
pub use util::{UtilState, UtilTracker, SCALE};

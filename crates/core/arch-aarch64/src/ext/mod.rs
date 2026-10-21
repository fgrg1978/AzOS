// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64-only extras with no counterpart on the other ISAs.

/// Hypervisor primitives (step H1): the resident EL2 stub, stage-2 tables, the
/// vGICv3 list-register model, the virtual timer.
pub mod hv;
/// Speculation mitigations (`A64_MIT_*`): the probe, the verdicts, `PSTATE.SSBS`.
pub mod mitigations;
/// SHA-256 on the ARMv8 Cryptographic Extension (wave 13).
pub mod sha2_ce;
/// FEAT_TLBIRANGE: the shootdown's range decomposition (pure) and its probe.
pub mod tlbi_range;
/// FEAT_WFxT: the probe's verdict and the WFET deadline (`spin.rs`).
pub mod wfxt;

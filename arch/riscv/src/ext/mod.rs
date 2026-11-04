// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RISC-V-only extras with no counterpart on the other ISAs.

/// Physical Memory Protection: the policy table and the M-mode programming helpers.
pub mod pmp;

/// The H extension: G-stage tables, VS-mode entry/exit, `vs*` CSR state,
/// exit decode, interrupt injection (hypervisor plan step H1).
pub mod hv;

/// Svnapot: 64 KiB NAPOT leaves, the encoders and the probe-gated switch
/// (Kconfig `RV_SVNAPOT`).
pub mod napot;

/// Ssqosid: the `srmcfg` resource-partition tag, its trap-safe probe and the
/// field widths (Kconfig `RV_SSQOSID`).
pub mod ssqosid;

/// `senvcfg`: what U-mode may do of the hart's environment (cache-block
/// instructions, pointer masking), its trap-safe probe and the per-hart
/// write (Kconfig `RV_SENVCFG`).
pub mod senvcfg;

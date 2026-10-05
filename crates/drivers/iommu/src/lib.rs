// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Minimal IOMMU support, RFC-0046 stage 1b — RISC-V IOMMU and SMMUv3.
//!
//! Scope, deliberately narrow (matches the brief): one translation stage,
//! per device either Bypass (identity: IOVA==PA, used while a device has
//! no domain) or SingleStage (one root page-table pointer per device, no
//! PASID/ATS/nested translation). No ATS, no MSI-remapping tables, no
//! multi-level device/stream tables beyond the one level each format
//! needs for a handful of QEMU `virt` PCI functions.
//!
//! # What is and is not verified here
//!
//! The RISC-V IOMMU field layouts (`riscv` module) and the SMMUv3 field
//! layouts (`smmuv3` module) were written from training-time knowledge of
//! the ratified RISC-V IOMMU spec and the Arm SMMUv3 architecture spec.
//! **Neither was cross-checked against the primary spec text or against
//! QEMU's model (`hw/riscv/riscv-iommu.c`, `hw/arm/smmuv3.c`) in this
//! session** — no network fetch was made. Treat every bit position as a
//! best-effort claim. The gate-3 canary ("a DMA to an unmapped IOVA
//! faults and is recorded") needs the real QEMU device to accept
//! whatever this crate programs, which has NOT been exercised against
//! QEMU here.
//!
//! What IS verified: the encode/decode round trips in
//! `azos_iommu_tests` (self-consistency of this crate's own bit
//! math) and the fault-cause classification logic (pure function, no
//! hardware dependency).
#![no_std]

pub mod riscv;
pub mod smmuv3;

/// Where a device's DMA traffic currently lands, independent of which
/// IOMMU flavour implements it — the one piece of state `crates/drivers/dma`
/// needs to know to answer `needs_bounce`'s `iommu_active` input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainMode {
    /// No translation: IOVA passed to the device equals the physical
    /// address. This is "IOMMU present but this device has no domain
    /// yet" — different from IOMMU absent entirely (VF2/K1 today, where
    /// this crate is not linked at all).
    Bypass,
    /// One-stage translation through a device-owned root page table.
    /// `root_ppn` is the physical page number of that table's root.
    SingleStage { root_ppn: u64 },
}

/// A DMA fault this crate can classify without knowing which flavour
/// (RISC-V IOMMU or SMMUv3) produced it — the durable record gate-3 asks
/// for is built from this, not from the flavour-specific raw record, so
/// the kernel-side record format doesn't need two shapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaFault {
    pub device_id: u32,
    /// The IOVA (or, for a page-table-structure fault, the address that
    /// access was walking) that faulted.
    pub fault_addr: u64,
    pub kind: FaultKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind {
    /// The IOVA has no valid translation — the gate-3 case: a DMA to an
    /// address nothing mapped.
    UnmappedIova,
    /// The device/stream table entry itself is missing, invalid, or
    /// malformed — a configuration bug, not a rogue DMA.
    BadDeviceEntry,
    /// Anything this crate's narrow cause-code map doesn't recognise.
    /// Recorded rather than dropped — an unrecognised cause is still
    /// evidence the fault path fired.
    Other(u32),
}

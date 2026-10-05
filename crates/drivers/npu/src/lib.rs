// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SpacemiT K1 NPU.

#![no_std]

// SpacemiT K1 NPU (Neural Processing Unit) — ~2 TOPS INT8 inference engine.
// F14: compiled for all builds; MMIO-mapped only on k1 feature.
pub mod npu;

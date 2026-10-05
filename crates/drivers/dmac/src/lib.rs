// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DMA controller (memcpy simulation on QEMU; JH7110 PDMA on VF2). The DMA
//! mapping API is a separate crate, `azos_dma`.

#![no_std]

// DMA controller (memcpy sim on QEMU; JH7110 PDMA on VF2).
#[allow(dead_code)]
pub mod dma;

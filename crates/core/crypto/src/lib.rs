// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cryptographic primitives for AzOS (F07).
//!
//! `no_std`, suitable for bare-metal RISC-V/aarch64 targets. Most of this
//! crate (SHA-256, AES-128, the OTA/anti-rollback logic) is hand-rolled with
//! no external dependencies; `ed25519.rs` and `x25519.rs` are the exception —
//! they depend on the vetted `ed25519-dalek`/`curve25519-dalek` crates
//! (`default-features = false`, no_std-compatible) rather than a hand-rolled
//! implementation, specifically BECAUSE hand-rolling asymmetric-crypto
//! verification is the class of mistake task #213 existed to fix (see that
//! module's docs).

#![no_std]

pub mod ct;
pub mod sha256;
pub mod aes;
pub mod x25519;
pub mod secure_channel;
pub mod ed25519;
pub mod entropy;

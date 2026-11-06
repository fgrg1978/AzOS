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

// The x86_64 kernel runs with no SIMD state at CPL0; the RustCrypto ciphers
// would pick SSE2/AVX2/AES-NI from CPUID (tools/build/kconfig_to_cargo.py
// passes these cfgs to every kernel build).
#[cfg(all(
    target_arch = "x86_64",
    target_os = "none",
    not(all(chacha20_force_soft, poly1305_force_soft, aes_force_soft))
))]
compile_error!("x86_64 bare metal needs --cfg chacha20_force_soft --cfg poly1305_force_soft --cfg aes_force_soft");

pub mod ct;
pub mod sha256;
pub mod aes;
pub mod x25519;
pub mod secure_channel;
pub mod ed25519;
pub mod sig;
pub mod entropy;
pub mod hkdf;
pub mod dice;
pub mod chachapoly;
pub mod noise;
pub mod wkdm;
pub mod keystore;

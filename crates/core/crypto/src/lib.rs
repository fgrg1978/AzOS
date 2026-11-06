// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cryptographic primitives for AzOS (F07).
//!
//! `no_std`, no allocation. The crate holds the protocol code (Noise, the
//! secure channel, the keystore, the DRBG, key derivation); every primitive
//! has one source, a vetted crate: RustCrypto's `sha2`, `hmac`, `hkdf`,
//! `chacha20`, `poly1305`, `chacha20poly1305`, `aes` and `ctr`, and
//! `curve25519-dalek` / `ed25519-dalek`. The CPU's SHA-2 instructions sit
//! behind the same SHA-256 API (`sha256`).

#![no_std]

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

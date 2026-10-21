// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of signed application packages (`crates/core/pkg`, plan D14).
//!
//! Three buckets, as everywhere in this tree. Tests that DISCRIMINATE a check
//! say which canary turns them red (`Cargo.toml` lists the features); tests
//! that do not discriminate one (shape, round trips) say nothing.

#![cfg(test)]

use azos_pkg::container::{key_id, HEADER_LEN};
use azos_pkg::{admit, verify, Device, HwClass, Refusal, SigAlg};
use azos_topology::emit::{emit_caps, emit_sched};
use azos_topology::{parse_caps, parse_sched, Binding, Topology};
use ed25519_dalek::{Signer, SigningKey};

extern crate alloc;

mod api;
mod apply;
mod azvol_mount;
mod build;
mod cases;
mod format;
mod loader_admit;
mod python;
mod service;
mod tftp_source;
mod tool;
mod update;
mod volume_key;

pub use build::*;

/// The signing key of the package author the device admits.
pub fn author() -> SigningKey {
    SigningKey::from_bytes(&[0xA1; 32])
}

/// A key the device does not admit.
pub fn stranger() -> SigningKey {
    SigningKey::from_bytes(&[0xB2; 32])
}

/// The topology key (the device owner's): signs CAPS.TOM, so the signer table.
pub fn owner() -> SigningKey {
    SigningKey::from_bytes(&[0x5a; 32])
}

/// A `.SIG` sidecar (the `DSIG` of `azos_crypto::sig`) signing `msg` with `key`.
pub fn dsig(key: &SigningKey, msg: &[u8]) -> Vec<u8> {
    let mut v = b"DSIG".to_vec();
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&64u16.to_le_bytes());
    v.extend_from_slice(&key.sign(msg).to_bytes());
    v
}

/// `[signer.acme]` for `key`, with a ceiling.
pub fn signer_text(name: &str, key: &SigningKey, extra: &str) -> String {
    let id = key_id(SigAlg::Ed25519 as u16, key.verifying_key().as_bytes());
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    format!("[signer.{name}]\nkey_id = \"{hex}\"\n{extra}")
}

/// The ceiling the well-behaved fixtures run under.
pub const CEILING: &str = "mem_pages_max = 64\nwarrants = [\"endpoint:endpoint.acme\", \"memobj:stream.\"]\n";

/// The device's text: the built-in topology as CAPS.TOM + SCHED.TOM, the first
/// with `signers` appended. Owned by the test, so rows and signers borrow it.
pub struct Device0 {
    pub caps: String,
    pub sched: String,
}

impl Device0 {
    pub fn with_signers(signers: &str) -> Self {
        let mut t = Box::new(Topology::empty());
        azos_topology::fill_default_minimal(&mut t);
        let mut sched = String::new();
        emit_sched(&t, &mut sched).unwrap();
        let b = Binding { sched_sha256: Some(azos_crypto::sha256::sha256(sched.as_bytes())), ..Binding::default() };
        let mut caps = String::new();
        emit_caps(&t, &b, &mut caps).unwrap();
        caps.push('\n');
        caps.push_str(signers);
        Self { caps, sched }
    }

    /// The device as the installer sees it: the topology its signed files hold.
    pub fn topology(&self) -> Box<Topology<'_>> {
        let mut t = Box::new(Topology::empty());
        parse_sched(self.sched.as_bytes(), &mut t).expect("SCHED.TOM");
        parse_caps(self.caps.as_bytes(), &mut t).expect("CAPS.TOM");
        t
    }
}

/// The interfaces this fixture device serves.
pub const API: &[(&str, u32)] = &[("Names", 1), ("Decisions", 2)];

pub fn device() -> Device<'static> {
    Device { hwclass: HwClass::Sbc, abi: azos_abi::ABI_VERSION, epoch_floor: 0, api: API }
}

/// Verify then admit, as the installer does, returning the first refusal.
pub fn install(bytes: &[u8], dev0: &Device0) -> Result<azos_pkg::Admitted, Refusal> {
    let mut topo = dev0.topology();
    let v = verify(bytes, &topo)?;
    admit(&v, v.pkg.rows, &mut topo, &device())
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A package builder: the Rust mirror of `tools/azpkg.py build` + `sign`.

use azos_crypto::sha256::sha256;
use azos_pkg::container::{message, HEADER_LEN, MAGIC};
use ed25519_dalek::{Signer, SigningKey};

/// What an author writes.
#[derive(Clone)]
pub struct Spec {
    pub name: String,
    pub version: String,
    pub abi: u32,
    pub hardware: Vec<&'static str>,
    pub api: Vec<(&'static str, u32)>,
    pub images: Vec<(String, Vec<u8>)>,
    pub rows: String,
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Spec {
    /// A package with one image, `ACME.ELF`, and its row.
    pub fn acme() -> Self {
        Spec {
            name: "acme-vision".into(),
            version: "1.2.0".into(),
            abi: azos_abi::ABI_VERSION,
            hardware: vec!["sbc", "desktop"],
            api: vec![("Names", 1)],
            images: vec![("ACME.ELF".into(), (0..300u32).map(|i| (i * 7) as u8).collect())],
            rows: row("ACME.ELF", "best_effort", 20, "{ kind = \"endpoint\", target = \"endpoint.acme\", perm = \"rw\" }"),
        }
    }

    pub fn meta(&self) -> String {
        let mut m = format!(
            "format = 1\nname = \"{}\"\nversion = \"{}\"\nabi = {}\nhardware = [{}]\nsbom_sha256 = \"{}\"\n",
            self.name,
            self.version,
            self.abi,
            self.hardware.iter().map(|h| format!("\"{h}\"")).collect::<Vec<_>>().join(", "),
            hex(&sha256(b"sbom")),
        );
        if !self.api.is_empty() {
            m.push_str("\n[api]\n");
            for (n, l) in &self.api {
                m.push_str(&format!("{n} = {l}\n"));
            }
        }
        for (n, data) in &self.images {
            m.push_str(&format!("\n[image.{n}]\nsize = {}\nsha256 = \"{}\"\n", data.len(), hex(&sha256(data))));
        }
        m
    }
}

/// A `[task.NAME]` row in the topology's syntax.
pub fn row(name: &str, class: &str, prio: u8, grants: &str) -> String {
    format!("[task.{name}]\nclass = \"{class}\"\npriority = {prio}\nmem_pages = 32\ncaps = [\n    {grants},\n]\n")
}

/// Assemble the container from parts, signing with `key` under `alg_id`.
pub fn assemble(alg_id: u16, key: &[u8], sig: &[u8], meta: &[u8], rows: &[u8], images: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&MAGIC);
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&alg_id.to_le_bytes());
    b.extend_from_slice(&(key.len() as u16).to_le_bytes());
    b.extend_from_slice(&(sig.len() as u16).to_le_bytes());
    for n in [meta.len(), rows.len(), images.len()] {
        b.extend_from_slice(&(n as u32).to_le_bytes());
    }
    assert_eq!(b.len(), HEADER_LEN);
    for part in [key, sig, meta, rows, images] {
        b.extend_from_slice(part);
    }
    b
}

/// Build and sign `spec` with `key`.
pub fn build(spec: &Spec, key: &SigningKey) -> Vec<u8> {
    let (meta, rows) = (spec.meta(), spec.rows.clone());
    let images: Vec<u8> = spec.images.iter().flat_map(|(_, d)| d.clone()).collect();
    let msg = message(1, meta.as_bytes(), rows.as_bytes());
    let sig = key.sign(&msg).to_bytes();
    assemble(1, key.verifying_key().as_bytes(), &sig, meta.as_bytes(), rows.as_bytes(), &images)
}

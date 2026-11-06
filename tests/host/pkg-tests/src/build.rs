// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A package builder: the Rust mirror of `tools/image/azpkg.py build` + `sign`.

use azos_crypto::sha256::sha256;
use azos_pkg::container::{message, HEADER_LEN, MAGIC};
use ed25519_dalek::{Signer, SigningKey};

/// What an author writes.
#[derive(Clone)]
pub struct Spec {
    pub name: String,
    pub version: String,
    pub abi: u32,
    pub sec_epoch: u32,
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
            sec_epoch: 0,
            hardware: vec!["sbc", "desktop"],
            api: vec![("Names", 1)],
            images: vec![("ACME.ELF".into(), (0..300u32).map(|i| (i * 7) as u8).collect())],
            rows: row("ACME.ELF", "best_effort", 20, "{ kind = \"endpoint\", target = \"endpoint.acme\", perm = \"rw\" }"),
        }
    }

    pub fn meta(&self) -> String {
        let mut m = format!(
            "format = 1\nname = \"{}\"\nversion = \"{}\"\nabi = {}\nsec_epoch = {}\nhardware = [{}]\nsbom_sha256 = \"{}\"\n",
            self.name,
            self.version,
            self.abi,
            self.sec_epoch,
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

/// One package an index lists.
#[derive(Clone)]
pub struct Offer {
    pub name: String,
    pub version: String,
    pub sec_floor: Option<String>,
    pub id: [u8; 32],
    pub file: String,
}

impl Offer {
    /// The offer of the package `bytes` holds, as its repository would list it.
    pub fn of(bytes: &[u8], file: &str, sec_floor: Option<&str>) -> Self {
        let p = azos_pkg::Package::parse(bytes).unwrap();
        let m = azos_pkg::Meta::parse(p.meta).unwrap();
        Offer { name: m.name.into(), version: m.version.into(), sec_floor: sec_floor.map(Into::into), id: p.id(), file: file.into() }
    }
}

/// The text of an index body listing `offers` (sorted by name, as the format wants).
pub fn index_body(serial: u32, offers: &[Offer]) -> String {
    let mut sorted = offers.to_vec();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut t = format!("format = 1\nserial = {serial}\n");
    for o in &sorted {
        t.push_str(&format!("\n[pkg.{}]\nversion = \"{}\"\n", o.name, o.version));
        if let Some(f) = &o.sec_floor {
            t.push_str(&format!("sec_floor = \"{f}\"\n"));
        }
        t.push_str(&format!("id = \"{}\"\nfile = \"{}\"\n", hex(&o.id), o.file));
    }
    t
}

/// Assemble an index file from parts.
pub fn assemble_index(alg_id: u16, key: &[u8], sig: &[u8], body: &[u8]) -> Vec<u8> {
    let mut b = azos_pkg::index::MAGIC.to_vec();
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&alg_id.to_le_bytes());
    b.extend_from_slice(&(key.len() as u16).to_le_bytes());
    b.extend_from_slice(&(sig.len() as u16).to_le_bytes());
    b.extend_from_slice(&(body.len() as u32).to_le_bytes());
    for part in [key, sig, body] {
        b.extend_from_slice(part);
    }
    b
}

/// Sign the index body `body` with `key`.
pub fn build_index(body: &str, key: &SigningKey) -> Vec<u8> {
    let sig = key.sign(&azos_pkg::index::message(1, body.as_bytes())).to_bytes();
    assemble_index(1, key.verifying_key().as_bytes(), &sig, body.as_bytes())
}

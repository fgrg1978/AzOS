// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The container and the metadata parser, byte by byte.

use super::*;
use azos_pkg::container::ParseError;
use azos_pkg::meta::{Meta, MetaError};
use azos_pkg::Package;

#[test]
fn the_container_splits_into_its_parts() {
    let bytes = build(&Spec::acme(), &author());
    let p = Package::parse(&bytes).unwrap();
    assert_eq!((p.alg_id, p.key.len(), p.sig.len()), (1, 32, 64));
    assert!(p.meta.starts_with(b"format = 1"));
    assert_eq!(p.images.len(), 300);
    assert_eq!(p.message().len(), 78);
    // The id of the key is its algorithm and bytes, hashed.
    assert_eq!(p.key_id(), key_id(1, author().verifying_key().as_bytes()));
    assert_ne!(key_id(1, &[1; 32]), key_id(2, &[1; 32]));
}

/// No prefix of a package is one, and nothing may follow it.
#[test]
fn every_truncation_and_extension_is_refused() {
    let bytes = build(&Spec::acme(), &author());
    for n in 0..bytes.len() {
        assert!(Package::parse(&bytes[..n]).is_err(), "prefix {n}");
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(Package::parse(&longer).unwrap_err(), ParseError::Length);
    let mut bad = bytes.clone();
    bad[0] = b'X';
    assert_eq!(Package::parse(&bad).unwrap_err(), ParseError::Magic);
    let mut bad = bytes.clone();
    bad[4] = 2;
    assert_eq!(Package::parse(&bad).unwrap_err(), ParseError::Format(2));
    // Lengths that would wrap a narrow sum, or past a ceiling.
    let mut bad = bytes.clone();
    bad[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    bad[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(Package::parse(&bad).unwrap_err(), ParseError::Length);
    let mut bad = bytes.clone();
    bad[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(Package::parse(&bad).unwrap_err(), ParseError::Length);
}

fn meta_with(edit: impl Fn(&str) -> String) -> Result<(), MetaError> {
    let text = edit(&Spec::acme().meta());
    Meta::parse(text.as_bytes()).map(|_| ())
}

#[test]
fn the_metadata_is_read_exactly() {
    let text = Spec::acme().meta();
    let m = Meta::parse(text.as_bytes()).unwrap();
    assert_eq!((m.name, m.version, m.abi), ("acme-vision", "1.2.0", azos_abi::ABI_VERSION));
    assert!(m.runs_on(HwClass::Sbc) && m.runs_on(HwClass::Desktop));
    assert!(!m.runs_on(HwClass::Embedded) && !m.runs_on(HwClass::Server));
    assert_eq!(m.api(), &[("Names", 1)]);
    assert_eq!((m.images().len(), m.images()[0].name, m.images()[0].size), (1, "ACME.ELF", 300));
    // Comments, blank lines, CRLF.
    assert!(Meta::parse(text.replace('\n', "\r\n").replace("format", "# c\r\nformat").as_bytes()).is_ok());
}

#[test]
fn a_malformed_metadata_is_refused() {
    let cases: &[(&str, Box<dyn Fn(&str) -> String>, MetaError)] = &[
        ("format 2", Box::new(|t| t.replacen("format = 1", "format = 2", 1)), MetaError::Format),
        ("format not first", Box::new(|t| t.replacen("format = 1\n", "", 1).replacen("version", "format = 1\nversion", 1)), MetaError::Format),
        ("repeated name", Box::new(|t| t.replacen("name", "name = \"x\"\nname", 1)), MetaError::Repeated),
        ("unknown key", Box::new(|t| t.replacen("abi", "colour = 1\nabi", 1)), MetaError::Unknown),
        ("name outside its alphabet", Box::new(|t| t.replace("acme-vision", "acme vision")), MetaError::Value),
        ("name with a quote", Box::new(|t| t.replace("\"acme-vision\"", "\"acme\\\"x\"")), MetaError::Value),
        ("epoch repeated", Box::new(|t| t.replacen("sec_epoch", "sec_epoch = 1\nsec_epoch", 1)), MetaError::Repeated),
        ("epoch not a number", Box::new(|t| t.replacen("sec_epoch = 0", "sec_epoch = \"0\"", 1)), MetaError::Value),
        ("missing epoch", Box::new(|t| t.replacen("sec_epoch", "#sec_epoch", 1)), MetaError::Missing),
        ("abi leading zero", Box::new(|t| t.replacen("abi = ", "abi = 0", 1)), MetaError::Value),
        ("unknown hardware", Box::new(|t| t.replace("\"sbc\"", "\"toaster\"")), MetaError::Value),
        ("hardware twice", Box::new(|t| t.replace("\"desktop\"", "\"sbc\"")), MetaError::Value),
        ("empty hardware", Box::new(|t| t.replace("[\"sbc\", \"desktop\"]", "[]")), MetaError::Value),
        ("short sbom hash", Box::new(|t| t.replacen("sbom_sha256 = \"", "sbom_sha256 = \"00", 1)), MetaError::Value),
        ("upper-case hash", Box::new(|t| t.replacen("sbom_sha256 = \"", "sbom_sha256 = \"A", 1).replacen("A", "A", 1)), MetaError::Value),
        ("missing abi", Box::new(|t| t.replacen("abi", "#abi", 1)), MetaError::Missing),
        ("no image", Box::new(|t| t.split("[image.").next().unwrap().to_string()), MetaError::Missing),
        ("image without a hash", Box::new(|t| t.replace("\nsha256 =", "\n#sha256 =")), MetaError::Missing),
        ("image not 8.3", Box::new(|t| t.replace("ACME.ELF", "ACMEACMEA.ELF")), MetaError::Value),
        ("image lower case", Box::new(|t| t.replace("ACME.ELF", "acme.ELF")), MetaError::Value),
        ("image not an ELF", Box::new(|t| t.replace("ACME.ELF", "ACME.BIN")), MetaError::Value),
        ("image path", Box::new(|t| t.replace("ACME.ELF", "../ACME.ELF")), MetaError::Value),
        ("image twice", Box::new(|t| format!("{t}\n[image.ACME.ELF]\nsize = 1\nsha256 = \"{}\"\n", "00".repeat(32))), MetaError::Repeated),
        ("zero size", Box::new(|t| t.replace("size = 300", "size = 0")), MetaError::Value),
        ("size twice", Box::new(|t| t.replace("size = 300", "size = 300\nsize = 300")), MetaError::Repeated),
        ("unknown section", Box::new(|t| format!("{t}\n[extra]\n")), MetaError::Unknown),
        ("api level zero", Box::new(|t| t.replace("Names = 1", "Names = 0")), MetaError::Value),
        ("api twice", Box::new(|t| t.replace("Names = 1", "Names = 1\nNames = 1")), MetaError::Repeated),
        ("api after an image", Box::new(|t| format!("{}\n[api]\nX = 1\n", t.replace("\n[api]\nNames = 1\n", ""))), MetaError::Unknown),
        ("api twice as a section", Box::new(|t| format!("{}\n[api]\nX = 1\n", t)), MetaError::Repeated),
        ("a line that is nothing", Box::new(|t| format!("{t}garbage\n")), MetaError::Syntax),
    ];
    for (what, edit, want) in cases {
        assert_eq!(meta_with(edit), Err(*want), "{what}");
    }
    assert_eq!(Meta::parse(&[0xFF, 0xFE]).map(|_| ()), Err(MetaError::Text));
    // More images or levels than the Kconfig tables hold.
    let many: String = (0..azos_pkg::MAX_IMAGES + 1)
        .map(|i| format!("\n[image.I{i}.ELF]\nsize = 1\nsha256 = \"{}\"\n", "00".repeat(32)))
        .collect();
    let head = Spec::acme().meta().split("[image.").next().unwrap().to_string();
    assert_eq!(Meta::parse(format!("{head}{many}").as_bytes()).map(|_| ()), Err(MetaError::TooMany));
}

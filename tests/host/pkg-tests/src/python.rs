// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A package built and signed by `tools/azpkg.py`, verified by this crate: the
//! two implementations of the container, the signed message and the metadata
//! agree byte for byte. Skipped (and says so) where `python3` or its
//! `cryptography` package is not there.

use super::*;
use std::path::{Path, PathBuf};
use std::process::Command;

fn azpkg() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tools/azpkg.py")
}

/// The interpreter that can run the tool: `$PYTHON` (as the Makefile has it),
/// then Homebrew's, then whatever `python3` is; the first that has `tomllib`
/// and `cryptography`.
fn python() -> Option<String> {
    let mut candidates: Vec<String> = std::env::var("PYTHON").ok().into_iter().collect();
    candidates.extend(["/opt/homebrew/bin/python3".to_string(), "python3".to_string()]);
    candidates.into_iter().find(|p| {
        Command::new(p)
            .args(["-c", "import tomllib, cryptography"])
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

/// `azpkg.py args...` in `dir`; `None` when no interpreter can run the tool.
fn run(dir: &Path, args: &[&str]) -> Option<(bool, String)> {
    let out = Command::new(python()?).arg(azpkg()).args(args).current_dir(dir).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    Some((out.status.success(), text))
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("azos-pkg-tests-{tag}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

const PACKAGE_TOML: &str = r#"
[package]
name = "pyvision"
version = "0.3.1"
hardware = ["sbc"]
licence = "Apache-2.0"
rows = "rows.toml"

[api]
Names = 1

[image."PYVIS.ELF"]
path = "vis.elf"
licence = "Apache-2.0 OR MIT"

[[component]]
name = "libfoo"
version = "1.0"
licence = "MIT"
"#;

const ROWS: &str = "format = 5\n[task.PYVIS.ELF]\nclass = \"best_effort\"\npriority = 20\nmem_pages = 32\n\
caps = [\n    { kind = \"endpoint\", target = \"endpoint.acme\", perm = \"rw\" },\n]\n";

/// The package the tool built, signed by a key it generated; `None` to skip.
fn built(tag: &str) -> Option<(PathBuf, String, Vec<u8>)> {
    let d = scratch(tag);
    std::fs::write(d.join("package.toml"), PACKAGE_TOML).unwrap();
    std::fs::write(d.join("rows.toml"), ROWS).unwrap();
    std::fs::write(d.join("vis.elf"), (0..777u32).map(|i| (i * 13) as u8).collect::<Vec<_>>()).unwrap();
    let (ok, out) = run(&d, &["keygen", "author"])?;
    assert!(ok, "{out}");
    let kid = out.split('"').nth(1).expect("key_id = \"..\"").to_string();
    let (ok, out) = run(&d, &["build", "package.toml", "-o", "p.azpkg"])?;
    assert!(ok, "{out}");
    let (ok, out) = run(&d, &["sign", "p.azpkg", "--key", "author.priv"])?;
    assert!(ok, "{out}");
    let sbom = std::fs::read(d.join("p.spdx.json")).unwrap();
    Some((d, kid, sbom))
}

fn device_for(kid: &str) -> Device0 {
    Device0::with_signers(&format!(
        "[signer.pyauthor]\nkey_id = \"{kid}\"\nmem_pages_max = 64\nwarrants = [\"endpoint:endpoint.acme\"]\n"))
}

#[test]
fn a_package_built_and_signed_by_the_tool_installs() {
    let Some((d, kid, sbom)) = built("ok") else { eprintln!("skipped: python3 + cryptography not available"); return };
    let bytes = std::fs::read(d.join("p.azpkg")).unwrap();
    let dev0 = device_for(&kid);
    let mut topo = dev0.topology();
    let v = verify(&bytes, &topo).expect("the tool's package verifies");
    assert_eq!((v.meta.name, v.meta.version), ("pyvision", "0.3.1"));
    // The SBOM that travels beside the package is the one the manifest names.
    assert_eq!(v.meta.sbom_sha256, azos_crypto::sha256::sha256(&sbom));
    let a = admit(&v, v.pkg.rows, &mut topo, &device()).expect("and is admitted");
    assert_eq!(a.rows, 1);
    // The tool's own verdict agrees.
    let (ok, out) = run(&d, &["verify", "p.azpkg", "--signer", &kid, "--sbom", "p.spdx.json"]).unwrap();
    assert!(ok, "{out}");
    // And on what the package is called: the id both sides compute.
    assert!(out.contains(&format!("id {}", hex(&v.id))), "{out}");
    // The key id the tool prints is the one the Rust side computes.
    assert_eq!(kid, hex(&v.pkg.key_id()));
}

/// The unsigned package `build` writes is refused by both sides.
///
/// **Canary** `pkg-verify-skip-canary` / `pkg-signer-canary`: the device side
/// of this assertion goes red.
#[test]
fn what_the_tool_builds_before_signing_is_refused() {
    let Some((d, kid, _)) = built("unsigned") else { eprintln!("skipped"); return };
    let (ok, _) = run(&d, &["build", "package.toml", "-o", "u.azpkg"]).unwrap();
    assert!(ok);
    let bytes = std::fs::read(d.join("u.azpkg")).unwrap();
    assert_eq!(install(&bytes, &device_for(&kid)), Err(Refusal::Algorithm(0)));
    let (ok, out) = run(&d, &["verify", "u.azpkg", "--any-signer"]).unwrap();
    assert!(!ok && out.contains("unsigned"), "{out}");
}

/// A byte changed anywhere after signing is refused by both implementations.
#[test]
fn a_tampered_package_is_refused_by_both() {
    let Some((d, kid, _)) = built("tamper") else { eprintln!("skipped"); return };
    let good = std::fs::read(d.join("p.azpkg")).unwrap();
    let dev0 = device_for(&kid);
    // Every region: key, signature, metadata, rows, images. (The key bytes
    // change the signer; the rest the signature or an image hash.)
    for at in [HEADER_LEN + 3, HEADER_LEN + 40, HEADER_LEN + 96 + 10, good.len() - 800 - 20, good.len() - 5] {
        let mut b = good.clone();
        b[at] ^= 0x04;
        std::fs::write(d.join("t.azpkg"), &b).unwrap();
        assert!(install(&b, &dev0).is_err(), "device accepted a change at {at}");
        let (ok, out) = run(&d, &["verify", "t.azpkg", "--signer", &kid]).unwrap();
        assert!(!ok, "the tool accepted a change at {at}: {out}");
    }
}

#[test]
fn the_tool_refuses_a_licence_off_the_allowlist_and_a_foreign_section() {
    let Some((d, _, _)) = built("lint") else { eprintln!("skipped"); return };
    std::fs::write(d.join("package.toml"), PACKAGE_TOML.replace("\"Apache-2.0 OR MIT\"", "\"GPL-3.0-only\"")).unwrap();
    let (ok, out) = run(&d, &["build", "package.toml", "-o", "g.azpkg"]).unwrap();
    assert!(!ok && out.contains("GPL-3.0-only"), "{out}");
    let (ok, out) = run(&d, &["lint", "package.toml"]).unwrap();
    assert!(!ok, "{out}");
    let (ok, out) = run(&d, &["lint", "package.toml", "--allow", "GPL-3.0-only"]).unwrap();
    assert!(ok, "{out}");
    // A component the SBOM carries is linted too.
    std::fs::write(d.join("package.toml"), PACKAGE_TOML.replace("licence = \"MIT\"", "licence = \"LicenseRef-vendor\"")).unwrap();
    let (ok, out) = run(&d, &["build", "package.toml", "-o", "g.azpkg"]).unwrap();
    assert!(!ok && out.contains("LicenseRef-vendor"), "{out}");
    // Rows that carry policy are refused before anything is built.
    std::fs::write(d.join("package.toml"), PACKAGE_TOML).unwrap();
    std::fs::write(d.join("rows.toml"), format!("{ROWS}[operator]\npubkey = \"00\"\n")).unwrap();
    let (ok, out) = run(&d, &["build", "package.toml", "-o", "g.azpkg"]).unwrap();
    assert!(!ok && out.contains("[operator]"), "{out}");
}

#[test]
fn the_tools_own_selftest_passes() {
    let d = scratch("selftest");
    let Some((ok, out)) = run(&d, &["selftest"]) else { eprintln!("skipped"); return };
    assert!(ok, "{out}");
}

#[test]
fn the_sbom_is_spdx_and_deterministic() {
    let Some((d, _, sbom)) = built("sbom") else { eprintln!("skipped"); return };
    let text = String::from_utf8(sbom.clone()).unwrap();
    for needle in ["\"spdxVersion\": \"SPDX-2.3\"", "\"dataLicense\": \"CC0-1.0\"", "\"SHA256\"", "\"libfoo\"",
                   "\"relationshipType\": \"DESCRIBES\"", "\"./PYVIS.ELF\""] {
        assert!(text.contains(needle), "{needle}\n{text}");
    }
    let (ok, _) = run(&d, &["build", "package.toml", "-o", "again.azpkg", "--sbom-out", "again.json"]).unwrap();
    assert!(ok);
    assert_eq!(std::fs::read(d.join("again.json")).unwrap(), sbom, "two builds, one SBOM");
    // The unsigned build is the signed one without its 32-byte key and 64-byte signature.
    assert_eq!(std::fs::read(d.join("again.azpkg")).unwrap().len() + 96, std::fs::read(d.join("p.azpkg")).unwrap().len());
}

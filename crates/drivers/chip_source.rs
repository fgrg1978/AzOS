// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The chip-logic crates' source fingerprint (wave 12, DRVPLACE "same
// source"), shared by their build scripts with `include!`. A chip crate
// (crates/drivers/ina219, crates/drivers/buzzer) is written once and hosted
// twice: in ring 3 and in the kernel. Its build script hashes its own `src/`
// and generates `SOURCE_MARKER`, the bytes `AZOS-CHIP-SRC <name> <hex>`;
// each host prints them at start, which keeps them in the binary, and
// tools/chip_source_check.py requires every host binary to carry the marker
// of the source in the tree. A host that stops linking the crate (a copy of
// the logic, a fork of it) carries no marker, or a stale one, and fails.
//
// FNV-1a, 64 bit, over every regular file under `src/` in byte order of the
// path relative to `src/` (`/`-separated): the path, a 0 byte, the contents,
// a 0 byte. tools/chip_source_check.py computes the same value.

fn chip_source_fingerprint(name: &str) {
    use std::path::{Path, PathBuf};
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .expect("chip source: read src/")
            .map(|e| e.expect("chip source: dir entry").path())
            .collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let src = Path::new(&manifest).join("src");
    println!("cargo:rerun-if-changed=src");
    let mut files = Vec::new();
    walk(&src, &mut files);
    let mut rel: Vec<(String, PathBuf)> = files
        .into_iter()
        .map(|p| {
            let r = p.strip_prefix(&src).expect("under src/").to_string_lossy().replace('\\', "/");
            (r, p)
        })
        .collect();
    rel.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |bytes: &[u8]| {
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    for (r, p) in &rel {
        println!("cargo:rerun-if-changed={}", p.display());
        eat(r.as_bytes());
        eat(&[0]);
        eat(&std::fs::read(p).expect("chip source: read file"));
        eat(&[0]);
    }
    let marker = format!("AZOS-CHIP-SRC {name} {h:016x}");
    let out = Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("chip_source.rs");
    std::fs::write(
        out,
        format!(
            "/// The chip source fingerprint (`crates/drivers/chip_source.rs`).\n\
             pub const SOURCE_HASH: u64 = {h:#018x};\n\
             /// `AZOS-CHIP-SRC <name> <hex>`: what every host prints at start.\n\
             pub const SOURCE_MARKER: [u8; {len}] = *b\"{marker}\";\n",
            len = marker.len()
        ),
    )
    .expect("chip source: write OUT_DIR/chip_source.rs");
}

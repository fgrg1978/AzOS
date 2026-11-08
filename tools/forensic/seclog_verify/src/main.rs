// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `seclog_verify [--tpm-anchor HEX] [--witness CAPTURE] EXPORT...`: check an
//! exported security log. EXPORT is a `KLOGn.TXT` file or a directory of
//! them (the volume `logd` writes). Exit 0 intact, 1 incomplete, 2 evidence
//! of tampering, 3 a usage or read error.

use seclog_verify::{hex32, parse_witness, render, verify, Options};
use std::path::Path;

fn usage(why: &str) -> ! {
    eprintln!("seclog_verify: {why}\nusage: seclog_verify [--tpm-anchor HEX] [--witness CAPTURE] EXPORT...");
    std::process::exit(3);
}

fn read(p: &Path, files: &mut Vec<Vec<u8>>) {
    if p.is_dir() {
        let Ok(rd) = std::fs::read_dir(p) else { usage(&format!("cannot read {}", p.display())) };
        let mut names: Vec<_> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
        names.sort();
        for n in names {
            let f = n.file_name().map(|f| f.to_string_lossy().to_ascii_uppercase()).unwrap_or_default();
            if f.starts_with("KLOG") && f.ends_with(".TXT") {
                read(&n, files);
            }
        }
    } else {
        match std::fs::read(p) {
            Ok(b) => files.push(b),
            Err(e) => usage(&format!("cannot read {}: {e}", p.display())),
        }
    }
}

fn main() {
    let mut opts = Options::default();
    let mut files = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--tpm-anchor" => {
                let v = args.next().unwrap_or_else(|| usage("--tpm-anchor needs a value"));
                opts.tpm_anchor = Some(hex32(&v).unwrap_or_else(|| usage("--tpm-anchor takes 64 hex digits")));
            }
            "--witness" => {
                let v = args.next().unwrap_or_else(|| usage("--witness needs a file"));
                let text = std::fs::read(&v).unwrap_or_else(|e| usage(&format!("cannot read {v}: {e}")));
                opts.witness.extend(parse_witness(&String::from_utf8_lossy(&text)));
            }
            "-h" | "--help" => usage("check an exported security log"),
            _ => read(Path::new(&a), &mut files),
        }
    }
    if files.is_empty() {
        usage("no export given");
    }
    let r = verify(&files, &opts);
    print!("{}", render(&r));
    std::process::exit(r.verdict.exit_code());
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The two match tables of `azos_hwbus` (see `src/tables.rs`).
//!
//! Native: every `crates/drivers/*/hwbus.ids`, one `<driver> <selector>
//! [boot] [if=<KCONFIG_SYMBOL>]` per line. A line whose symbol is not `y` in
//! `.config` is left out (no `.config`: every line is kept). Linux:
//! `tools/build/lx_device_table.py`. Then two checks, each a build failure that
//! names the ids: no native pattern overlaps a Linux one, and no two native
//! drivers claim overlapping patterns. The native table is also emitted by
//! driver (`DRIVERS`, `native_drivers!`): the ids half of each record.

use std::collections::BTreeMap;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[allow(dead_code)]
#[path = "src/pattern.rs"]
mod pattern;
use pattern::{first_overlap, Pattern, ANY};

struct Native {
    pattern: String,
    driver: String,
    boot: bool,
    origin: String,
}

struct Linux {
    pattern: String,
    class: String,
    module: String,
}

fn lit(p: &Pattern<'_>) -> String {
    let f = |v: u32| if v == ANY { "crate::pattern::ANY".to_string() } else { format!("{v:#x}") };
    match p {
        Pattern::Pci { vendor, device, class, class_mask } => format!(
            "Pattern::Pci {{ vendor: {}, device: {}, class: {:#x}, class_mask: {:#x} }}",
            f(*vendor), f(*device), class, class_mask
        ),
        Pattern::Dt(s) => format!("Pattern::Dt({s:?})"),
        Pattern::Virtio(id) => format!("Pattern::Virtio({id})"),
    }
}

fn sel(p: &str) -> Pattern<'_> {
    Pattern::parse(p).unwrap()
}

fn config(root: &Path) -> Option<BTreeMap<String, String>> {
    let path = env::var("KCONFIG_CONFIG").map(PathBuf::from).unwrap_or_else(|_| root.join(".config"));
    println!("cargo:rerun-if-env-changed=KCONFIG_CONFIG");
    println!("cargo:rerun-if-changed={}", path.display());
    if !path.exists() {
        return None;
    }
    let map = azos_config::parse_config(path.to_str().unwrap())
        .unwrap_or_else(|e| panic!("azos_hwbus: cannot read {}: {e}", path.display()));
    Some(map.into_iter().collect())
}

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest.ancestors().nth(3).expect("workspace root").to_path_buf();
    let cfg = config(&root);

    // ── Native ──────────────────────────────────────────────────────────
    let drivers_dir = root.join("crates/drivers");
    println!("cargo:rerun-if-changed={}", drivers_dir.display());
    let mut files: Vec<PathBuf> = fs::read_dir(&drivers_dir)
        .expect("crates/drivers")
        .filter_map(|e| e.ok())
        .map(|e| e.path().join("hwbus.ids"))
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    let mut native: Vec<Native> = Vec::new();
    for f in &files {
        println!("cargo:rerun-if-changed={}", f.display());
        let text = fs::read_to_string(f).unwrap();
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap().trim();
            if line.is_empty() {
                continue;
            }
            let origin = format!("{}:{}", f.strip_prefix(&root).unwrap().display(), n + 1);
            let mut it = line.split_whitespace();
            let (driver, selector) = match (it.next(), it.next()) {
                (Some(d), Some(s)) => (d, s),
                _ => panic!("azos_hwbus: {origin}: want `<driver> <selector> [if=SYMBOL]`"),
            };
            let mut keep = true;
            let mut boot = false;
            for opt in it {
                if opt == "boot" {
                    boot = true;
                    continue;
                }
                let Some(sym) = opt.strip_prefix("if=") else {
                    panic!("azos_hwbus: {origin}: unknown option {opt:?} (boot, if=SYMBOL)");
                };
                if let Some(cfg) = &cfg {
                    keep &= cfg.get(sym).map(|v| v == "y").unwrap_or(false);
                }
            }
            if Pattern::parse(selector).is_none() {
                panic!("azos_hwbus: {origin}: {selector:?} is not a selector (pci:V:D, pciclass:C:M, dt:S, virtio:N)");
            }
            if keep {
                native.push(Native { pattern: selector.to_string(), driver: driver.to_string(), boot, origin });
            }
        }
    }

    // ── Linux ───────────────────────────────────────────────────────────
    let gen = root.join("tools/build/lx_device_table.py");
    println!("cargo:rerun-if-changed={}", gen.display());
    println!("cargo:rerun-if-changed={}", root.join("crates/drivers/lx/DEVICE_SOURCES").display());
    let out = Command::new("python3")
        .arg(&gen)
        .arg(&root)
        .output()
        .unwrap_or_else(|e| panic!("azos_hwbus: cannot run python3 {}: {e}", gen.display()));
    if !out.status.success() {
        panic!("azos_hwbus: {} failed:\n{}", gen.display(), String::from_utf8_lossy(&out.stderr));
    }
    let mut linux: Vec<Linux> = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut it = line.split_whitespace();
        let (Some(class), Some(sel), Some(module)) = (it.next(), it.next(), it.next()) else {
            panic!("azos_hwbus: lx_device_table printed {line:?}");
        };
        let module = module.strip_prefix("module=").unwrap_or(module);
        if Pattern::parse(sel).is_none() {
            panic!("azos_hwbus: lx_device_table printed an unparsable selector {sel:?}");
        }
        linux.push(Linux { pattern: sel.to_string(), class: class.to_string(), module: module.to_string() });
    }

    // ── Checks ──────────────────────────────────────────────────────────
    if let Some((i, j)) = first_overlap(&native, &linux, |n| sel(&n.pattern), |l| sel(&l.pattern)) {
        let (n, l) = (&native[i], &linux[j]);
        panic!(
            "azos_hwbus: {} is in both tables: native driver {:?} ({}) and Linux module {:?} (class {:?}, {}). \
             One id has one owner: take it out of one of the two.",
            n.pattern, n.driver, n.origin, l.module, l.class, l.pattern
        );
    }
    for (i, a) in native.iter().enumerate() {
        let rest = &native[i + 1..];
        let other: Vec<&Native> = rest.iter().filter(|b| b.driver != a.driver).collect();
        if let Some((_, j)) = first_overlap(std::slice::from_ref(a), &other, |n| sel(&n.pattern), |n| sel(&n.pattern)) {
            let b = other[j];
            panic!(
                "azos_hwbus: native drivers {:?} ({}) and {:?} ({}) both claim {} / {}",
                a.driver, a.origin, b.driver, b.origin, a.pattern, b.pattern
            );
        }
    }

    // ── Emit ────────────────────────────────────────────────────────────
    let mut s = String::from("// GENERATED by crates/drivers/hwbus/build.rs from the hwbus.ids files. Do not edit.\n");
    s.push_str("/// The native match table.\npub static NATIVE: &[NativeEntry] = &[\n");
    for n in &native {
        let p = Pattern::parse(&n.pattern).unwrap();
        let _ = writeln!(s, "    NativeEntry {{ pattern: {}, driver: {:?}, boot: {} }},", lit(&p), n.driver, n.boot);
    }
    s.push_str("];\n");

    // One record's ids per driver name, in first-appearance order, and the
    // macro a host builds its record table from.
    let mut drivers: Vec<(&str, Vec<&Native>)> = Vec::new();
    for n in &native {
        match drivers.iter_mut().find(|(d, _)| *d == n.driver) {
            Some((_, v)) => v.push(n),
            None => drivers.push((&n.driver, vec![n])),
        }
    }
    s.push_str("/// Every native driver's ids, one entry per driver.\npub const DRIVERS: &[DriverIds] = &[\n");
    for (name, lines) in &drivers {
        if let Some(odd) = lines.iter().find(|l| l.boot != lines[0].boot) {
            panic!("azos_hwbus: driver {name:?}: {} and {} disagree on `boot`", lines[0].origin, odd.origin);
        }
        let ids: Vec<String> = lines.iter().map(|l| lit(&Pattern::parse(&l.pattern).unwrap())).collect();
        let _ = writeln!(s, "    DriverIds {{ name: {:?}, ids: &[{}], boot: {} }},", name, ids.join(", "), lines[0].boot);
    }
    s.push_str("];\n");
    s.push_str(
        "/// Call `$m! { <index> <IDENT> ... }` with every entry of [`DRIVERS`]: its\n\
         /// index and its name as an identifier (`virtio-blk`: `VIRTIO_BLK`).\n\
         #[macro_export]\nmacro_rules! native_drivers {\n    ($m:ident) => {\n        $m! {",
    );
    for (i, (name, lines)) in drivers.iter().enumerate() {
        let id = name.to_ascii_uppercase().replace('-', "_");
        if !id.starts_with(|c: char| c.is_ascii_alphabetic()) || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            panic!("azos_hwbus: {}: driver name {name:?} is not an identifier once `-` reads `_`", lines[0].origin);
        }
        let _ = write!(s, " {i} {id}");
    }
    s.push_str(" }\n    };\n}\n");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out_dir.join("hwbus_native.rs"), s).unwrap();

    let mut s = String::from("// GENERATED by crates/drivers/hwbus/build.rs from tools/build/lx_device_table.py. Do not edit.\n");
    s.push_str("/// The Linux match table.\npub static LINUX: &[LinuxEntry] = &[\n");
    for l in &linux {
        let p = Pattern::parse(&l.pattern).unwrap();
        let _ = writeln!(
            s,
            "    LinuxEntry {{ pattern: {}, class: {:?}, module: {:?} }},",
            lit(&p), l.class, l.module
        );
    }
    s.push_str("];\n");
    fs::write(out_dir.join("hwbus_linux.rs"), s).unwrap();
}

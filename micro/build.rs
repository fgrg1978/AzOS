// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Links the image from the Kconfig window: reads the MICRO_* symbols of the
//! `.config` (`KCONFIG_CONFIG`, `make micro` sets it) and hands them to
//! `link.ld` as symbols. Everything else Kconfig says reaches the code as
//! `azos_limits` constants, like the main kernel's.

use std::path::PathBuf;

fn num(cfg: &azos_config::ConfigMap, key: &str) -> u64 {
    let v = cfg.get(key).unwrap_or_else(|| {
        panic!("azos_micro: {key} is not in the .config: build with `make micro` (config/defconfigs/generic-embedded-riscv64-dev+board-generic+micro.config)")
    });
    match v.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16),
        None => v.parse(),
    }
    .unwrap_or_else(|_| panic!("azos_micro: {key}={v} is not a number"))
}

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    // Outputs live under $AZOS_OUT (tools/lib/out_dir.py), never in the checkout.
    let out = PathBuf::from(std::env::var("AZOS_OUT").expect("azos_micro: AZOS_OUT is not set (see tools/lib/out_dir.py)"));
    println!("cargo:rerun-if-env-changed=AZOS_OUT");
    let config = std::env::var("KCONFIG_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| out.join("build").join("micro.config"));
    println!("cargo:rerun-if-changed={}", config.display());
    println!("cargo:rerun-if-env-changed=KCONFIG_CONFIG");
    println!("cargo:rerun-if-changed=link.ld");
    let cfg = azos_config::parse_config(config.to_str().unwrap())
        .unwrap_or_else(|e| panic!("azos_micro: cannot read {}: {e}", config.display()));
    if cfg.get("MICRO").map(String::as_str) != Some("y") {
        panic!("azos_micro: {} does not set MICRO (use config/defconfigs/generic-embedded-riscv64-dev+board-generic+micro.config)", config.display());
    }
    // The bin only: the library is also built for the host test suite.
    let kib = 1024u64;
    let defs = [
        ("__ram_base", num(&cfg, "MICRO_RAM_BASE")),
        ("__ram_len", num(&cfg, "MICRO_RAM_KIB") * kib),
        ("__pool_len", num(&cfg, "MICRO_POOL_KIB") * kib),
        ("__contig_len", num(&cfg, "MICRO_CONTIG_KIB") * kib),
        ("__kstack_len", num(&cfg, "MICRO_KSTACK_BYTES")),
        ("__pmp_grain", 1 << num(&cfg, "MICRO_PMP_GRAIN_LOG2")),
    ];
    // The signed topology the image carries (`make micro-topology`).
    let topo = std::env::var("MICRO_TOPOLOGY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| out.join("build").join("micro").join("topology"));
    for f in ["CAPS.TOM", "CAPS.SIG", "SCHED.TOM"] {
        println!("cargo:rerun-if-changed={}", topo.join(f).display());
    }
    println!("cargo:rerun-if-env-changed=MICRO_TOPOLOGY_DIR");
    println!("cargo:rustc-env=MICRO_TOPOLOGY_DIR={}", topo.display());
    println!("cargo:rustc-link-arg-bins=-T{}", manifest.join("link.ld").display());
    for (sym, val) in defs {
        println!("cargo:rustc-link-arg-bins=--defsym={sym}={val}");
    }
}

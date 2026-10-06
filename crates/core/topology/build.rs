// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Embeds the Ed25519 public key used to verify signed AZOS files —
//! `CAPS.TOML` + `SCHED.TOML` (RFC-0005/0011) and, as of W2-B5,
//! `CONFIG.INI` — one key, one `.SIG`-sidecar mechanism, shared by every
//! file this project asks the operator to sign.
//!
//! Mirrors `crates/core/ota/build.rs`'s embedding pattern exactly (same
//! rationale: a build script instead of a feature flag, so nobody has to
//! remember to pass one, and the produced binary is reproducible from the
//! same key file). Deliberately a SEPARATE key from OTA's
//! `tools/keys/prod_pub.bin`: firmware-image trust and
//! configuration/capability trust are different authorities, and RFC-0011
//! anchors each in its own OTP/eFuse slot on real hardware.
//!
//! **No default key in a production build** (wave 11, RFC-0054 finding F-7).
//! This used to fall back to `tools/keys/test_pub.bin` whenever
//! `TOPOLOGY_PUBKEY_PATH` was unset, while OTA's build script falls back to
//! `prod_pub.bin`: a board build that forgot the variable verified CONFIG.SIG,
//! and the ring-3 ML service its MLP.SIG/POLICY.SIG, against a TEST key whose
//! private half sits next to it. Now the key comes from exactly one of:
//!
//! * `TOPOLOGY_PUBKEY_PATH` (non-empty): that file, which must exist and be
//!   32 bytes — an explicitly named key that cannot be read fails the build,
//!   it is never replaced by an all-zero key;
//! * the `dev-key` feature (the kernel's `qemu` feature enables it, and so do
//!   the host test crates): `tools/keys/test_pub.bin`, the key
//!   `tools/gen_test_key.py` generates on demand, or an all-zero key if it has
//!   not been generated (every signature check then fails closed);
//! * neither: the build FAILS, with one line saying which two to choose from.
//!
//! An empty `TOPOLOGY_PUBKEY_PATH` counts as unset (a Makefile `export` of an
//! unset variable passes an empty one).

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

const PUBKEY_LEN: usize = 32;

fn main() {
    emit_target_cfgs();
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let dest = out_dir.join("topology_pubkey.rs");

    // crates/core/topology/ -> up three levels = repo root.
    let manifest_dir =
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let default_path = PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("..")
        .join("tools")
        .join("keys")
        .join("test_pub.bin");
    println!("cargo:rerun-if-env-changed=TOPOLOGY_PUBKEY_PATH");
    let explicit = env::var("TOPOLOGY_PUBKEY_PATH").ok().filter(|p| !p.is_empty());
    let dev_key = env::var_os("CARGO_FEATURE_DEV_KEY").is_some();

    let bytes: [u8; PUBKEY_LEN] = match (explicit, dev_key) {
        (Some(p), _) => {
            let key_path = PathBuf::from(p);
            println!("cargo:rerun-if-changed={}", key_path.display());
            match fs::read(&key_path) {
                Ok(data) if data.len() == PUBKEY_LEN => {
                    let mut arr = [0u8; PUBKEY_LEN];
                    arr.copy_from_slice(&data);
                    arr
                }
                Ok(data) => fail(&format!(
                    "TOPOLOGY_PUBKEY_PATH={} is {} bytes, not a {}-byte Ed25519 public key",
                    key_path.display(), data.len(), PUBKEY_LEN)),
                Err(e) => fail(&format!(
                    "TOPOLOGY_PUBKEY_PATH={} cannot be read: {}", key_path.display(), e)),
            }
        }
        (None, true) => {
            println!("cargo:rerun-if-changed={}", default_path.display());
            match fs::read(&default_path) {
                Ok(data) if data.len() == PUBKEY_LEN => {
                    let mut arr = [0u8; PUBKEY_LEN];
                    arr.copy_from_slice(&data);
                    arr
                }
                Ok(data) => {
                    println!(
                        "cargo:warning=topology: {} has wrong size ({} != {}) — \
                         using all-zero key, every CAPS.TOML/SCHED.TOML/CONFIG.INI \
                         signature check fails closed",
                        default_path.display(),
                        data.len(),
                        PUBKEY_LEN
                    );
                    [0u8; PUBKEY_LEN]
                }
                // Quiet fallback — a fresh clone before `tools/gen_test_key.py`
                // has run. Every signature check fails closed against an
                // all-zero key: an unprovisioned dev build trusts nothing.
                Err(_) => [0u8; PUBKEY_LEN],
            }
        }
        (None, false) => fail(
            "no signing key for a production build: set TOPOLOGY_PUBKEY_PATH to the \
             fleet's 32-byte Ed25519 public key, or build with the `dev-key` feature \
             (the kernel's `qemu` feature enables it) to embed tools/keys/test_pub.bin",
        ),
    };

    let mut out = fs::File::create(&dest).expect("write topology_pubkey.rs");
    writeln!(out, "// Auto-generated by build.rs — do not edit.").unwrap();
    write!(
        out,
        "pub const TRUSTED_PUBKEY: [u8; {}] = [",
        PUBKEY_LEN
    )
    .unwrap();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            write!(out, ", ").unwrap();
        }
        write!(out, "0x{:02x}", b).unwrap();
    }
    writeln!(out, "];").unwrap();
}

/// The shape of the built-in topology that depends on the machine, as cfgs.
///
/// A few rows of `builder.rs` name a resource of one QEMU `virt` machine
/// (`mmio.2`, `irq.11`/`irq.34`, `irq.100`/`irq.1000`): they exist only in a
/// kernel (`target_os = "none"`) and differ by ISA. The host emitter
/// (`tests/host/topology-tests/src/bin/topo_emit.rs`) writes the CAPS.TOM a
/// kernel of one ISA would build, so it must compile those rows for a target
/// it is not running on. `emit-target-riscv64` / `emit-target-aarch64` ask for
/// that shape; without either, the cfgs follow the real target, so a kernel
/// and the host suites build exactly what they built before.
///
/// * `topo_bare`: the rows a kernel has and a host build does not;
/// * `topo_arch_riscv64` / `topo_arch_aarch64`: the ISA's row variants
///   (each implies `topo_bare`).
fn emit_target_cfgs() {
    println!("cargo:rustc-check-cfg=cfg(topo_bare)");
    println!("cargo:rustc-check-cfg=cfg(topo_arch_riscv64)");
    println!("cargo:rustc-check-cfg=cfg(topo_arch_aarch64)");
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let want_rv = env::var_os("CARGO_FEATURE_EMIT_TARGET_RISCV64").is_some();
    let want_arm = env::var_os("CARGO_FEATURE_EMIT_TARGET_AARCH64").is_some();
    if want_rv && want_arm {
        fail("emit-target-riscv64 and emit-target-aarch64 are exclusive: one ISA's topology at a time");
    }
    let bare = os == "none";
    let (rv, arm) = if want_rv || want_arm {
        (want_rv, want_arm)
    } else {
        (bare && arch == "riscv64", bare && arch == "aarch64")
    };
    if bare || rv || arm {
        println!("cargo:rustc-cfg=topo_bare");
    }
    if rv {
        println!("cargo:rustc-cfg=topo_arch_riscv64");
    }
    if arm {
        println!("cargo:rustc-cfg=topo_arch_aarch64");
    }
}

/// Stop the build with one line on stderr (cargo prints it under the failing
/// build script), not a panic backtrace: the gate greps this line.
fn fail(why: &str) -> ! {
    eprintln!("error: azos_topology: {}", why);
    std::process::exit(1);
}

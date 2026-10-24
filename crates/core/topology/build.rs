// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Embeds the public key used to verify signed AZOS files —
//! `CAPS.TOML` + `SCHED.TOML` and, as of W2-B5,
//! `CONFIG.INI` — one key, one `.SIG`-sidecar mechanism, shared by every
//! file this project asks the operator to sign.
//!
//! Mirrors `crates/core/ota/build.rs`'s embedding pattern exactly (same
//! rationale: a build script instead of a feature flag, so nobody has to
//! remember to pass one, and the produced binary is reproducible from the
//! same key file). Deliberately a SEPARATE key from OTA's
//! `tools/keys/prod_pub.bin`: firmware-image trust and
//! configuration/capability trust are different authorities, and the secure-boot
//! design anchors each in its own OTP/eFuse slot on real hardware.
//!
//! **No default key in a production build** (wave 11).
//! This used to fall back to `tools/keys/test_pub.bin` whenever
//! `TOPOLOGY_PUBKEY_PATH` was unset, while OTA's build script falls back to
//! `prod_pub.bin`: a board build that forgot the variable verified CONFIG.SIG,
//! and the ring-3 inference service its POLICY.SIG and model bundles, against a TEST key whose
//! private half sits next to it. Now the key comes from exactly one of:
//!
//! * `TOPOLOGY_PUBKEY_PATH` (non-empty): that file, which must exist and be
//!   a key of the configured algorithm (its length
//!   is checked where the key is embedded, `azos_crypto::sig::key_array`) — an
//!   explicitly named key that cannot be read fails the build, it is never
//!   replaced by an all-zero key;
//! * the `dev-key` feature (the kernel's `qemu` feature enables it, and so do
//!   the host test crates): `tools/keys/test_pub.bin`, the key
//!   `tools/sign/gen_test_key.py` generates on demand, or an all-zero key if it has
//!   not been generated (every signature check then fails closed);
//! * neither: the build FAILS, with one line saying which two to choose from.
//!
//! **No TEST key in a release image** (Kconfig `BUILD_TYPE_RELEASE`, owner
//! decision wave 15): a bare-metal build whose `KCONFIG_CONFIG` selects it
//! fails when the key it would embed is the TEST key, through the `dev-key`
//! fallback and also when `TOPOLOGY_PUBKEY_PATH` names it (compared by bytes
//! against `tools/keys/test_pub.bin`, so a copy under another name is refused
//! too). The `make` board targets refuse the same key earlier, with
//! `tools/sign/check_board_keys.py`.
//!
//! An empty `TOPOLOGY_PUBKEY_PATH` counts as unset (a Makefile `export` of an
//! unset variable passes an empty one).

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

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
    // Kconfig BUILD_TYPE_RELEASE and BUILD_TYPE_CERTIFIABLE: a bare-metal image built from a release
    // .config never embeds the TEST key through the `dev-key` fallback
    // (the `make` board targets refuse an explicit TEST key path with
    // tools/sign/check_board_keys.py). Host builds (the test crates) are not
    // images and keep the fallback.
    let bare = env::var("CARGO_CFG_TARGET_OS").map(|o| o == "none" || o == "azos").unwrap_or(false);
    let release = bare && release_config();
    let explicit_given = explicit.is_some();
    if dev_key && explicit.is_none() && release {
        fail("Kconfig BUILD_TYPE_RELEASE (as BUILD_TYPE_CERTIFIABLE) refuses the TEST key: the `dev-key` feature \
              (the kernel's `qemu` feature) would embed tools/keys/test_pub.bin; set \
              TOPOLOGY_PUBKEY_PATH to the fleet's public key (`make vf2`/`k1`/`rpi5`/\
              `build-fleet`), or select BUILD_TYPE_DEV");
    }
    // The same refusal by CONTENT for a key named explicitly: a release image
    // never embeds the TEST key whatever path (or copy) TOPOLOGY_PUBKEY_PATH
    // names. The TEST key is tools/keys/test_pub.bin (generated per clone, so
    // there is no constant to compare against); absent, there is no test key
    // to confuse it with.
    let refuse_test_key = |bytes: &[u8]| {
        println!("cargo:rerun-if-changed={}", default_path.display());
        if explicit_given && release
            && fs::read(&default_path).map(|t| t[..] == *bytes).unwrap_or(false)
        {
            fail("BUILD_TYPE_RELEASE (Kconfig BUILD_TYPE, as BUILD_TYPE_CERTIFIABLE) refuses the TEST signing key: \
                  TOPOLOGY_PUBKEY_PATH names a key whose bytes equal tools/keys/test_pub.bin; \
                  set TOPOLOGY_PUBKEY_PATH to the fleet's own public key, or select \
                  BUILD_TYPE_DEV");
        }
    };

    let bytes: Vec<u8> = match (explicit, dev_key) {
        (Some(p), _) => {
            let key_path = PathBuf::from(p);
            println!("cargo:rerun-if-changed={}", key_path.display());
            match fs::read(&key_path) {
                Ok(data) if !data.is_empty() => {
                    refuse_test_key(&data);
                    data
                }
                Ok(_) => fail(&format!("TOPOLOGY_PUBKEY_PATH={} is empty", key_path.display())),
                Err(e) => fail(&format!(
                    "TOPOLOGY_PUBKEY_PATH={} cannot be read: {}", key_path.display(), e)),
            }
        }
        (None, true) => {
            println!("cargo:rerun-if-changed={}", default_path.display());
            // Quiet fallback when the file is absent — a fresh clone before
            // `tools/sign/gen_test_key.py` has run. No key is an empty slice, which
            // `key_array` turns into an all-zero key: every signature check
            // fails closed, an unprovisioned dev build trusts nothing.
            fs::read(&default_path).unwrap_or_default()
        }
        (None, false) => fail(
            "no signing key for a production build: set TOPOLOGY_PUBKEY_PATH to the \
             fleet's public key, or build with the `dev-key` feature \
             (the kernel's `qemu` feature enables it) to embed tools/keys/test_pub.bin",
        ),
    };

    let mut out = fs::File::create(&dest).expect("write topology_pubkey.rs");
    writeln!(out, "// Auto-generated by build.rs — do not edit.").unwrap();
    write!(out, "pub const TRUSTED_PUBKEY_BYTES: &[u8] = &[").unwrap();
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
/// (`mmio.dt:...`, `irq.11`/`irq.34`, `irq.100`/`irq.1000`): they exist only in a
/// kernel (`target_os = "none"`) and differ by ISA. The host emitter
/// (`tests/host/topology-tests/src/bin/topo_emit.rs`) writes the CAPS.TOM a
/// kernel of one ISA would build, so it must compile those rows for a target
/// it is not running on. `emit-target-riscv64` / `emit-target-aarch64` /
/// `emit-target-x86_64` ask for that shape; without one, the cfgs follow the
/// real target, so a kernel and the host suites build exactly what they built
/// before.
///
/// * `topo_bare`: the rows a kernel has and a host build does not;
/// * `topo_arch_riscv64` / `topo_arch_aarch64`: the ISA's row variants
///   (each implies `topo_bare`). x86_64 has no variant cfg: its kernel is
///   `topo_bare` with neither, and so is its emitter.
fn emit_target_cfgs() {
    println!("cargo:rustc-check-cfg=cfg(topo_bare)");
    println!("cargo:rustc-check-cfg=cfg(topo_arch_riscv64)");
    println!("cargo:rustc-check-cfg=cfg(topo_arch_aarch64)");
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let want_rv = env::var_os("CARGO_FEATURE_EMIT_TARGET_RISCV64").is_some();
    let want_arm = env::var_os("CARGO_FEATURE_EMIT_TARGET_AARCH64").is_some();
    let want_x86 = env::var_os("CARGO_FEATURE_EMIT_TARGET_X86_64").is_some();
    if [want_rv, want_arm, want_x86].iter().filter(|&&w| w).count() > 1 {
        fail("emit-target-riscv64, emit-target-aarch64 and emit-target-x86_64 are exclusive: one ISA's topology at a time");
    }
    let bare = os == "none" || os == "azos" || want_x86;
    let (rv, arm) = if want_rv || want_arm || want_x86 {
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

/// Does the build name a release or certifiable configuration (KCONFIG_CONFIG
/// with Kconfig BUILD_TYPE_RELEASE or BUILD_TYPE_CERTIFIABLE)? Only an explicit KCONFIG_CONFIG counts: every kernel
/// build the Makefile and the gate run sets it, while the QEMU disks' ring-3
/// services (`--features dev-key`, no KCONFIG_CONFIG) are QEMU-only images
/// and must keep building after `make defconfig-<board>` leaves a release
/// workspace `.config`.
fn release_config() -> bool {
    println!("cargo:rerun-if-env-changed=KCONFIG_CONFIG");
    let Ok(path) = env::var("KCONFIG_CONFIG").map(PathBuf::from) else {
        return false;
    };
    println!("cargo:rerun-if-changed={}", path.display());
    fs::read_to_string(&path)
        .map(|c| {
            c.lines().any(|l| {
                let l = l.trim();
                l == "CONFIG_BUILD_TYPE_RELEASE=y" || l == "CONFIG_BUILD_TYPE_CERTIFIABLE=y"
            })
        })
        .unwrap_or(false)
}

/// Stop the build with one line on stderr (cargo prints it under the failing
/// build script), not a panic backtrace: the gate greps this line.
fn fail(why: &str) -> ! {
    eprintln!("error: azos_topology: {}", why);
    std::process::exit(1);
}

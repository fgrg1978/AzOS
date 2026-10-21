// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The IDL crates' own tests, run from their own manifests (see Cargo.toml).

use std::path::PathBuf;
use std::process::Command;

fn crate_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../crates/core").join(name)
}

fn host() -> String {
    let out = Command::new("rustc").arg("-vV").output().expect("rustc -vV");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("host: ").map(str::to_owned))
        .expect("a host line")
}

/// `cargo test` in `dir` with the nested run's own environment: nothing of
/// this run's cargo (target dir, rustflags, toolchain pin) leaks in.
fn cargo_test(dir: PathBuf, pre: &[&str], post: &[&str]) {
    let mut c = Command::new("cargo");
    c.args(pre).args(["test", "--offline", "--release"]).args(post).current_dir(&dir);
    for (k, _) in std::env::vars() {
        if k.starts_with("CARGO") && k != "CARGO_HOME" || k == "RUSTFLAGS" || k == "RUSTC" || k == "RUSTUP_TOOLCHAIN" {
            c.env_remove(k);
        }
    }
    let out = c.output().expect("cargo");
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "cargo test in {} failed:\n{text}", dir.display());
    assert!(text.contains("test result: ok."), "no test ran in {}:\n{text}", dir.display());
}

/// The `#[azos_interface]` expansion (unit tests in the proc-macro crate).
#[test]
fn the_macro_crates_own_tests_pass() {
    cargo_test(crate_dir("idl-macros"), &[], &[]);
}

/// The runtime and its stub round trips. `azos_idl` is `no_std`, so the
/// workspace's bare-metal default target is replaced by the host's.
#[test]
fn the_runtime_round_trips_pass() {
    cargo_test(crate_dir("idl"), &["+stable"], &["--target", &host()]);
}

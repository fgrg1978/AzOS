// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `login_enroll` binary the gate's rows enrol users with, run as they run
//! it: what it prints is the verifier of `src/lib.rs`'s known answer, and a bad
//! argument is an error, not a verifier.

use std::process::Command;

fn run(args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_login_enroll")).args(args).output().expect("login_enroll runs");
    (out.status.success(), String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// **Canary.** Change a label of `login_public`: the pinned line is red.
#[test]
fn the_tool_prints_the_pinned_verifier_and_refuses_what_derives_nothing() {
    let seed = "42".repeat(32);
    let ok = ["--seed", seed.as_str(), "--user", "alice", "--owner", "1", "--passphrase", "correct horse"];
    assert_eq!(run(&ok), (true, "66fe1e6f1e9dc367e25fe8d19bd4b3e8622b13ff61491d99dc183faa8cd7a9d2".to_string()));
    let zero = "00".repeat(32);
    assert!(!run(&["--seed", zero.as_str(), "--user", "alice", "--owner", "1", "--passphrase", "x"]).0, "a board without a seed");
    assert!(!run(&["--seed", seed.as_str(), "--user", "alice", "--owner", "0", "--passphrase", "x"]).0, "owner roots start at 1");
    assert!(!run(&["--seed", "42", "--user", "alice", "--owner", "1", "--passphrase", "x"]).0, "a short seed");
}

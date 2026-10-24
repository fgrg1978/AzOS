// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `login_enroll`: the line of a `[login.NAME]` row that lets a user log in on
//! the console of one board.
//!
//!     login_enroll --seed <64 hex> --user NAME --owner N --passphrase TEXT
//!
//! `--seed` is the board's seed (the 32-byte key of the link-key record in
//! reserved tail sector 0 of its medium, the 8th sector from the end of an
//! image: `tools/sign/link_key_provision.py`), `--owner` the
//! user's root: the place of the `[login.NAME]` row in the signed topology plus
//! one (the first row is 1). Prints the 64 hex digits to list as the row's
//! `ssh_key` entry. The derivation is the kernel's own
//! (`azos_crypto::keystore::login_public`) and the credential is the terminal
//! server's (`azos_login::credential`), so what this prints is what the
//! `login` op of `keys` compares with.
//!
//! The passphrase is on the command line: this is a tool for a bench and for
//! the gate's fixtures. A deployment enrols on the board it enrols for.

use std::process::ExitCode;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (mut seed, mut user, mut owner, mut pass) = (None, None, None, None);
    while let Some(a) = args.next() {
        let v = args.next();
        match a.as_str() {
            "--seed" => seed = v,
            "--user" => user = v,
            "--owner" => owner = v,
            "--passphrase" => pass = v,
            _ => {
                eprintln!("login_enroll: unknown argument {a}");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(seed), Some(user), Some(owner), Some(pass)) = (seed, user, owner, pass) else {
        eprintln!("usage: login_enroll --seed <64 hex> --user NAME --owner N --passphrase TEXT");
        return ExitCode::from(2);
    };
    let Some(seed) = unhex(&seed) else {
        eprintln!("login_enroll: --seed is 64 hex digits");
        return ExitCode::from(2);
    };
    let Ok(owner) = owner.parse::<u32>() else {
        eprintln!("login_enroll: --owner is a number");
        return ExitCode::from(2);
    };
    if owner == 0 || user.len() > azos_login::NAME_MAX || user.is_empty() || pass.len() > azos_login::PASSPHRASE_MAX {
        eprintln!("login_enroll: --owner starts at 1, the name is 1..=16 bytes, the passphrase at most 128");
        return ExitCode::from(2);
    }
    let mut name = [0u8; azos_login::NAME_MAX];
    name[..user.len()].copy_from_slice(user.as_bytes());
    match azos_logind_tests::enroll::verifier(&seed, owner, &name, user.as_bytes(), pass.as_bytes()) {
        Some(p) => {
            println!("{}", hex(&p));
            ExitCode::SUCCESS
        }
        None => {
            eprintln!("login_enroll: the seed is all zeros: the board derives nothing");
            ExitCode::from(1)
        }
    }
}

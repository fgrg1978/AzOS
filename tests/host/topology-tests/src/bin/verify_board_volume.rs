// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Verifies a board volume's signatures with the kernel's own verifier code.
//!
//!     verify_board_volume <CONFIG.INI> <CONFIG.SIG> <device-id-hex> \
//!                         <MLP.RML> <MLP.SIG> <POLICY.GGF> <POLICY.SIG>
//!
//! `azos_topology::verify_config_sig_v2` for the config (the call the
//! kernel's `cfg_load_verified` makes) and `verify_signature` for the two ML
//! data files (the call the ring-3 ML service makes), both against
//! `TRUSTED_PUBKEY`, which is whatever key this binary was BUILT with:
//! `TOPOLOGY_PUBKEY_PATH=<fleet key> cargo run --bin verify_board_volume`.
//! Used by `tools/check_board_keys.py sigs` (wave 11 BOARDIMG). Exit 1 when any
//! signature does not verify.

use azos_topology::{verify_config_sig_v2, verify_signature, TRUSTED_PUBKEY};

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("verify_board_volume: cannot read {path}: {e}");
        std::process::exit(2);
    })
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 8 {
        eprintln!("usage: verify_board_volume CONFIG.INI CONFIG.SIG device-id-hex MLP.RML MLP.SIG POLICY.GGF POLICY.SIG");
        std::process::exit(2);
    }
    let hex = a[3].as_bytes();
    let mut id = [0u8; 16];
    if hex.len() != 32 {
        eprintln!("verify_board_volume: the device id is 32 hex digits");
        std::process::exit(2);
    }
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&a[3][2 * i..2 * i + 2], 16).unwrap_or_else(|_| {
            eprintln!("verify_board_volume: bad hex in the device id");
            std::process::exit(2);
        });
    }
    let mut bad = 0;
    match verify_config_sig_v2(&read(&a[1]), &read(&a[2]), &id, &TRUSTED_PUBKEY) {
        Ok(counter) => println!("CONFIG.SIG verified (counter {counter})"),
        Err(e) => {
            println!("CONFIG.SIG REFUSED: {e:?}");
            bad += 1;
        }
    }
    for (name, data, sig) in [("MLP.RML", &a[4], &a[5]), ("POLICY.GGF", &a[6], &a[7])] {
        match verify_signature(&read(data), &read(sig), &TRUSTED_PUBKEY) {
            Ok(()) => println!("{name} verified"),
            Err(e) => {
                println!("{name} REFUSED: {e:?}");
                bad += 1;
            }
        }
    }
    std::process::exit(if bad == 0 { 0 } else { 1 });
}

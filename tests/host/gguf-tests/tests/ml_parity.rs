// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The parity sweep the ML service's kernel smoke (`ml-kill-smoke`) ran under
//! QEMU, as a host test: the MLP over an 11 x 11 grid of range readings, class
//! and logit BITS, against an independent reference, first with the
//! compiled-in weights and then with the same weights loaded from an RMLP
//! file (the path `/fat/MLP.RML` takes in the service).
//!
//! One `#[test]`: `model_load_bytes` writes a process-wide static, and this
//! file is its own test binary, so nothing else races it.

use azos_ml::{argmax3, mlp_infer, model_is_loaded, model_load_bytes, RMLP_FILE_SIZE};

const IN: usize = 4;
const HID: usize = 8;
const OUT: usize = 3;

#[rustfmt::skip]
const W1: [f32; HID * IN] = [
     1.0, 0.0, 0.0, 0.0,
    -1.0, 0.0, 0.0, 0.0,
     0.0, 1.0, 0.0, 0.0,
     0.0,-1.0, 0.0, 0.0,
     1.0, 0.0, 0.0, 0.0,
     0.0, 0.0, 0.0, 0.0,
     0.0, 0.0, 0.0, 0.0,
     0.0, 0.0, 0.0, 0.0,
];
const B1: [f32; HID] = [-0.5, 0.3, -0.2, 0.25, -0.3, 0.0, 0.0, 0.0];
#[rustfmt::skip]
const W2: [f32; OUT * HID] = [
    2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 3.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 3.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
];
const B2: [f32; OUT] = [0.0; OUT];

/// The reference: the plain nested loops, written out here, not the library's.
fn reference(x: &[f32; IN], b2: &[f32; OUT]) -> [f32; OUT] {
    let mut h = [0.0f32; HID];
    for j in 0..HID {
        let mut acc = 0.0f32;
        for k in 0..IN {
            acc += W1[j * IN + k] * x[k];
        }
        h[j] = (B1[j] + acc).max(0.0);
    }
    let mut out = [0.0f32; OUT];
    for i in 0..OUT {
        let mut acc = 0.0f32;
        for j in 0..HID {
            acc += W2[i * HID + j] * h[j];
        }
        out[i] = b2[i] + acc;
    }
    out
}

/// An RMLP file (`tools/make_mlp.py`'s layout) of the reference weights.
fn rmlp(b2: &[f32; OUT]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"RMLP");
    for n in [1u32, IN as u32, HID as u32, OUT as u32, 0] {
        v.extend_from_slice(&n.to_le_bytes());
    }
    for f in W1.iter().chain(&B1).chain(&W2).chain(b2) {
        v.extend_from_slice(&f.to_le_bytes());
    }
    v
}

/// Points of the grid whose logit bits or class differ from the reference.
fn sweep_mismatches() -> usize {
    let mut bad = 0;
    for fi in 0..=10u16 {
        for ri in 0..=10u16 {
            let x = [(fi * 100) as f32 / 1000.0, (ri * 100) as f32 / 1000.0, 0.5, 0.9];
            let got = mlp_infer(&x);
            let want = reference(&x, &B2);
            let same_bits = (0..OUT).all(|k| got[k].to_bits() == want[k].to_bits());
            if !same_bits || argmax3(&got) != argmax3(&want) {
                bad += 1;
            }
        }
    }
    bad
}

#[test]
fn mlp_matches_the_reference_compiled_in_and_from_an_rmlp_file() {
    // The documented scenarios (lib.rs): go_forward, turn_right, stop.
    assert_eq!(argmax3(&mlp_infer(&[0.8, 0.3, 0.5, 0.9])), 0);
    assert_eq!(argmax3(&mlp_infer(&[0.6, 0.1, 0.5, 0.8])), 1);
    assert_eq!(argmax3(&mlp_infer(&[0.1, 0.5, 0.3, 0.7])), 2);

    // Compiled-in weights.
    assert!(!model_is_loaded());
    assert_eq!(sweep_mismatches(), 0, "compiled-in weights differ from the reference");

    // A refused file changes nothing.
    let good = rmlp(&B2);
    assert_eq!(good.len(), RMLP_FILE_SIZE);
    let mut bad_magic = good.clone();
    bad_magic[0] ^= 1;
    assert!(!model_load_bytes(&bad_magic));
    assert!(!model_load_bytes(&good[..RMLP_FILE_SIZE - 1]));
    assert!(!model_is_loaded());

    // The same weights from a file: bit-identical.
    assert!(model_load_bytes(&good));
    assert!(model_is_loaded());
    assert_eq!(sweep_mismatches(), 0, "weights loaded from an RMLP file differ from the reference");

    // Canary (discriminates): one bias off by a hair in the file must show.
    let mut tweaked_b2 = B2;
    tweaked_b2[2] = 0.015625;
    assert!(model_load_bytes(&rmlp(&tweaked_b2)));
    assert!(sweep_mismatches() > 0, "the sweep cannot see a changed weight");
}

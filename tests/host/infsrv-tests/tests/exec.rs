// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The backends: the answer of the CPU kernel is the model's, the dot product
//! is the one the caller names, and a model of the wrong shape is refused
//! before it is ever called.

use azos_infsrv_tests::*;
use infsrv::exec::{self, Exec, Kernel, RvvVerdict};

/// `cpu-ggml` computes the model: the answer is what the arithmetic on the
/// weights gives, for inputs that exercise both sides of every ReLU.
///
/// The expected answers are computed in this file from the weights, not by the
/// code under test.
#[test]
fn cpu_ggml_runs_the_model() {
    let e = Exec::scalar();
    assert_eq!(e.kernel(), Kernel::Scalar);
    for x in [[0.8f32, 0.3, 0.5, 0.9], [-1.0, 2.0, 0.0, 0.0], [3.0, -4.0, 1.0, 1.0], [-1.0, -1.0, -1.0, -1.0]] {
        let mut out = vec![0u8; 8];
        assert!(e.run(&model(), &tensor(&x), &mut out));
        assert_eq!(floats(&out, 2), model_answer(x), "{x:?}");
    }
}

/// The kernel is whatever dot product the caller passes: a dot that returns
/// a constant changes the answer, and one that sums in another order gives the
/// same answer on exactly-representable data. This is how the vector kernel is
/// plugged in on riscv64, so the plug is what is proven here; the instruction
/// sequence is proven by the start-up probe (`Exec::probe`) on the target.
///
/// **Canary.** Pass `dot_seq` to `gguf_mlp_infer_with` in `run_with` whatever
/// `dot` is: the constant row is red.
#[test]
fn the_dot_product_is_the_one_that_is_passed() {
    let x = [1.0f32, 2.0, 3.0, 4.0];
    let mut seq = vec![0u8; 8];
    assert!(exec::run_with(exec::dot_seq, &model(), &tensor(&x), &mut seq));
    let mut rev = vec![0u8; 8];
    let backwards = |a: &[f32], b: &[f32]| a.iter().zip(b).rev().map(|(p, q)| p * q).sum::<f32>();
    assert!(exec::run_with(backwards, &model(), &tensor(&x), &mut rev));
    assert_eq!(seq, rev, "exact data: any order of addition agrees");
    let mut k = vec![0u8; 8];
    assert!(exec::run_with(|_: &[f32], _: &[f32]| 7.0, &model(), &tensor(&x), &mut k));
    assert_ne!(seq, k);
    // Both layers took the constant: y0 = 0 + 7, y1 = 0.5 + 7.
    assert_eq!(floats(&k, 2), [7.0, 7.5]);
}

/// A tensor that is not a whole number of floats, or is too wide, is refused;
/// so is a blob that is not a GGUF file, or a model whose shape is not the
/// bundle's (`fits`, checked once at load).
#[test]
fn a_tensor_or_model_of_the_wrong_shape_is_refused() {
    let e = Exec::scalar();
    let mut out = vec![0u8; 8];
    assert!(!e.run(&model(), &[0u8; 15], &mut out));
    assert!(!e.run(&model(), &[0u8; 16], &mut [0u8; 7]));
    assert!(!e.run(&model(), &vec![0u8; 4 * (exec::MAX_ELEMS + 1)], &mut out));
    assert!(!e.run(b"nope", &[0u8; 16], &mut out));
    assert!(exec::fits(&model(), IN_BYTES, OUT_BYTES));
    assert!(!exec::fits(&model(), IN_BYTES + 4, OUT_BYTES), "input wider than w1");
    assert!(!exec::fits(&model(), IN_BYTES, OUT_BYTES + 4), "output wider than w2");
    assert!(!exec::fits(&model(), 0, OUT_BYTES));
    assert!(!exec::fits(&model(), 15, OUT_BYTES));
    assert!(!exec::fits(b"GGUF", IN_BYTES, OUT_BYTES));
}

/// Off riscv64 there is no vector kernel to take, whatever the capability word
/// says; on riscv64 a hart without V keeps the scalar kernel.
#[test]
fn the_vector_kernel_is_not_taken_where_it_is_not() {
    let (e, why) = Exec::probe(true);
    assert_eq!(e.kernel(), Kernel::Scalar);
    assert_eq!(why, RvvVerdict::NotThisIsa);
    assert_eq!(Exec::probe(false).0.kernel(), Kernel::Scalar);
}

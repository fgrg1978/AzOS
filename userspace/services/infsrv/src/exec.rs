// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The backends: the two ways this service runs a GGUF variant in process.
//!
//! * `cpu-ggml`: `azos_ml::ggml_nano`, whose dot product is the sequential
//!   loop. On every ISA.
//! * `rvv`: the same layers (same dequantisers, same loop over the output
//!   rows) with the dot product taken by the RISC-V vector unit, 16 floats at
//!   a time at VLEN 128. Only on riscv64, only when the vDSO's hardware
//!   capability word says the hart implements V
//!   (`azos_libsys::hwcap::HWCAP_RV_V`: what the CPU has and ring 3 may use),
//!   and only after the vector dot product has agreed with the sequential one
//!   on a probe vector ([`Exec::probe`]); a disagreement leaves the service on
//!   `cpu-ggml` and says so.
//!
//! Both are one backend of the bundle: a variant says `BACKEND_GGUF`, a file
//! the CPU runs; which kernel runs it is this machine's business, not the
//! publisher's, and a vector kernel only makes a run shorter than the signed
//! worst case. (A machine without it may be slower than the figure the
//! publisher measured; the overrun is charged back, [`crate::broker`].)
//!
//! A tensor is `f32`, little-endian, `n * 4` bytes, `n <= MAX_WIDTH`.

use azos_ml::ggml_nano::{gguf_mlp_infer, gguf_mlp_infer_with, MAX_WIDTH};
use azos_ml::gguf::GgufFile;

/// Elements of the biggest tensor either backend takes.
pub const MAX_ELEMS: usize = MAX_WIDTH;

/// Which dot product a run uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kernel {
    /// The sequential loop (`cpu-ggml`).
    Scalar,
    /// The vector unit (`rvv`).
    Rvv,
}

/// The backend a service runs its variants on.
#[derive(Clone, Copy, Debug)]
pub struct Exec {
    kernel: Kernel,
}

/// Why the vector kernel was not taken, for the start-up line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RvvVerdict {
    /// Taken.
    On,
    /// This ISA has none.
    NotThisIsa,
    /// The hart does not implement V, or ring 3 may not use it.
    NoHardware,
    /// The vector dot product disagreed with the sequential one: not trusted.
    Mismatch,
}

impl Exec {
    /// The scalar backend, which every ISA has.
    pub const fn scalar() -> Exec {
        Exec { kernel: Kernel::Scalar }
    }

    /// The best backend this hart has. `hart_has_v`: the capability word
    /// says V (ignored off riscv64). Returns the backend and why the vector
    /// kernel is on or off.
    pub fn probe(hart_has_v: bool) -> (Exec, RvvVerdict) {
        #[cfg(target_arch = "riscv64")]
        {
            if !hart_has_v {
                return (Exec::scalar(), RvvVerdict::NoHardware);
            }
            if !agrees(rvv::dot) {
                return (Exec::scalar(), RvvVerdict::Mismatch);
            }
            (Exec { kernel: Kernel::Rvv }, RvvVerdict::On)
        }
        #[cfg(not(target_arch = "riscv64"))]
        {
            let _ = hart_has_v;
            (Exec::scalar(), RvvVerdict::NotThisIsa)
        }
    }

    /// The kernel in use.
    pub const fn kernel(&self) -> Kernel {
        self.kernel
    }

    /// Run the GGUF `blob` on `input`, writing `output`. Both are `f32`
    /// tensors in little-endian bytes. `false` when the blob is not a
    /// two-layer MLP of these sizes (it was checked at load, so this is the
    /// service failing, not the caller).
    pub fn run(&self, blob: &[u8], input: &[u8], output: &mut [u8]) -> bool {
        match self.kernel {
            Kernel::Scalar => run_with(dot_seq, blob, input, output),
            #[cfg(target_arch = "riscv64")]
            Kernel::Rvv => run_with(rvv::dot, blob, input, output),
            #[cfg(not(target_arch = "riscv64"))]
            Kernel::Rvv => false,
        }
    }
}

/// The sequential dot product, the `cpu-ggml` kernel (the one
/// `azos_ml::gguf_mlp_infer` uses, written out so [`run_with`] can take it as
/// a value).
pub fn dot_seq(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    let mut acc = 0.0f32;
    for i in 0..n {
        acc += a[i] * b[i];
    }
    acc
}

/// [`Exec::run`] with the dot product named: how the tests prove the kernel is
/// the one that is used, and how the vector kernel is plugged in.
pub fn run_with(dot: impl Fn(&[f32], &[f32]) -> f32 + Copy, blob: &[u8], input: &[u8], output: &mut [u8]) -> bool {
    let (n_in, n_out) = (input.len() / 4, output.len() / 4);
    if input.len() % 4 != 0 || output.len() % 4 != 0 || n_in > MAX_ELEMS || n_out > MAX_ELEMS {
        return false;
    }
    let Some(gguf) = GgufFile::parse(blob) else { return false };
    let mut x = [0.0f32; MAX_ELEMS];
    for (i, c) in input.chunks_exact(4).enumerate() {
        x[i] = f32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    let mut y = [0.0f32; MAX_ELEMS];
    if !gguf_mlp_infer_with(dot, &gguf, &x[..n_in], &mut y[..n_out]) {
        return false;
    }
    for (i, c) in output.chunks_exact_mut(4).enumerate() {
        c.copy_from_slice(&y[i].to_le_bytes());
    }
    true
}

/// Whether `blob` is a model this service can run as the bundle says: a
/// two-layer MLP from `in_bytes` to `out_bytes` of `f32`. Checked once, at
/// load, by running it on zeros with the sequential kernel (the checks of
/// `gguf_mlp_infer` are the dimension checks), so a call never meets a model
/// of the wrong shape.
pub fn fits(blob: &[u8], in_bytes: u32, out_bytes: u32) -> bool {
    let (n_in, n_out) = ((in_bytes / 4) as usize, (out_bytes / 4) as usize);
    if in_bytes % 4 != 0 || out_bytes % 4 != 0 || n_in == 0 || n_out == 0 || n_in > MAX_ELEMS || n_out > MAX_ELEMS {
        return false;
    }
    let Some(gguf) = GgufFile::parse(blob) else { return false };
    let x = [0.0f32; MAX_ELEMS];
    let mut y = [0.0f32; MAX_ELEMS];
    gguf_mlp_infer(&gguf, &x[..n_in], &mut y[..n_out])
}

// arch-only: the probe of the RISC-V vector kernel; other ISAs have no `Kernel::Rvv` to check
/// A probe vector whose sums every order of addition gets exactly right (small
/// integers), long enough for a vector length that is not a multiple of the
/// register: the vector dot product must give the sequential one's answer.
#[cfg(target_arch = "riscv64")]
fn agrees(dot: impl Fn(&[f32], &[f32]) -> f32) -> bool {
    let (mut a, mut b) = ([0.0f32; 37], [0.0f32; 37]);
    for i in 0..37 {
        a[i] = (i % 7) as f32;
        b[i] = ((i * 3) % 5) as f32 - 2.0;
    }
    dot(&a, &b) == dot_seq(&a, &b)
}

// arch-only: the RISC-V vector unit has no counterpart in this program on other ISAs (they run the sequential kernel)
/// The RISC-V vector dot product. The same instruction sequence the kernel's
/// own (`crates/core/arch-riscv64/src/fp.rs`, `dot_f32_rvv`) uses, in this
/// program: LMUL 4, `vfredusum` into element 0 of v16.
#[cfg(target_arch = "riscv64")]
mod rvv {
    use core::arch::asm;

    pub fn dot(a: &[f32], b: &[f32]) -> f32 {
        let n = a.len().min(b.len());
        if n == 0 {
            return 0.0;
        }
        let mut result_bits: u32 = 0;
        let rp = &mut result_bits as *mut u32;
        let (ap, bp) = (a.as_ptr() as usize, b.as_ptr() as usize);
        // SAFETY: the loop reads `n` floats from each slice and stores one 32-bit
        // word at `rp`; `.option arch` enables the vector and float mnemonics
        // inside the block only (this target has neither type-level), and the
        // caller runs it only when the hart implements V and ring 3 may use it
        // (`Exec::probe`).
        unsafe {
            asm!(
                ".option push",
                ".option arch, +v, +f, +d",
                "vsetivli zero, 1, e32, m1, ta, ma",
                "vmv.v.i  v16, 0",
                "1:",
                "beqz     {rem}, 2f",
                "vsetvli  {vl}, {rem}, e32, m4, ta, ma",
                "vle32.v  v0, ({ap})",
                "vle32.v  v4, ({bp})",
                "vfmul.vv v8, v0, v4",
                "vfredusum.vs v16, v8, v16",
                "slli     {tmp}, {vl}, 2",
                "add      {ap}, {ap}, {tmp}",
                "add      {bp}, {bp}, {tmp}",
                "sub      {rem}, {rem}, {vl}",
                "j        1b",
                "2:",
                "vsetivli zero, 1, e32, m1, ta, ma",
                "vse32.v  v16, ({rp})",
                ".option pop",
                ap = inout(reg) ap => _,
                bp = inout(reg) bp => _,
                rem = inout(reg) n => _,
                vl = out(reg) _,
                tmp = out(reg) _,
                rp = in(reg) rp,
            );
        }
        f32::from_bits(result_bits)
    }
}

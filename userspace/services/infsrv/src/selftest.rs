// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The start-up self-test of the GGUF engine on the policy file.
//!
//! [`prepare`] reads `/fat/POLICY.GGF`, checks its Ed25519 signature
//! `/fat/POLICY.SIG` (see [`check_signature`], Kconfig
//! `INFER_MODEL_SIG_REQUIRED`) and, if it verifies, runs the three
//! classifications Phase C used to run in the kernel at boot, printed with the
//! same `[GGUF] n/3 tests passed` verdict the gate reads. The file is the
//! network of the behavior loop's bundle (`BEHAVIOR.MBL`), so the test says,
//! before the first call, whether the engine this image runs it on agrees with
//! the reference outputs. The lines keep the `[GGUF]` tag the gate rows
//! (`tools/gate/ci_check.sh`) read; the broker's own lines are `[infsrv]`.

use crate::out::{read_file, Line};
use crate::volume::{POLICY_PATH, POLICY_SIG_PATH};
use azos_libsys as sys;

// ── Startup: the model files ────────────────────────────────────────────────

/// What [`check_signature`] found for one data file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Signature {
    /// The sidecar verified against the trusted key.
    Verified,
    /// `CONFIG_INFER_MODEL_SIG_REQUIRED=n`: nothing was checked.
    NotRequired,
    /// No sidecar on the volume.
    Absent,
    /// A sidecar that is not a `DSIG` of the device's algorithm, or that does
    /// not verify.
    Bad,
}

/// Check `data` against the signature sidecar in `sig_path` — the
/// `CAPS.SIG`/`CONFIG.SIG` format and key
/// (`azos_topology::verify_signature`, `TRUSTED_PUBKEY`). The bytes
/// checked are the bytes the caller then uses: a file longer than the
/// caller's buffer was read truncated and fails here.
fn check_signature(data: &[u8], sig_path: &[u8]) -> Signature {
    if !azos_limits::INFER_MODEL_SIG_REQUIRED {
        return Signature::NotRequired;
    }
    // One byte more than a sidecar, so a longer one is seen as such.
    let mut sig = [0u8; azos_topology::SIDECAR_MAX + 1];
    match read_file(sig_path, &mut sig) {
        None => Signature::Absent,
        Some(n) if n <= azos_topology::SIDECAR_MAX => {
            match azos_topology::verify_signature(data, &sig[..n], &azos_topology::TRUSTED_PUBKEY) {
                Ok(()) => Signature::Verified,
                Err(_) => Signature::Bad,
            }
        }
        Some(_) => Signature::Bad,
    }
}

/// Phase C's boot self-test, moved out of the kernel with the inference.
fn gguf_self_test() {
    static mut BUF: [u8; 4096] = [0; 4096];
    // SAFETY: single-threaded program; the only reference to BUF.
    let buf = unsafe { &mut *(&raw mut BUF) };
    let Some(n) = read_file(POLICY_PATH, buf) else {
        sys::println(b"[GGUF] /fat/POLICY.GGF not found");
        return;
    };
    // Verified before the parser sees a byte (`verify.rs`'s ordering rule).
    match check_signature(&buf[..n], POLICY_SIG_PATH) {
        Signature::Absent => {
            sys::println(b"[GGUF] /fat/POLICY.GGF REFUSED: no /fat/POLICY.SIG -- self-test skipped");
            return;
        }
        Signature::Bad => {
            sys::println(b"[GGUF] /fat/POLICY.GGF REFUSED: bad signature in /fat/POLICY.SIG -- self-test skipped");
            return;
        }
        Signature::Verified | Signature::NotRequired => {}
    }
    let Some(gguf) = azos_ml::gguf::GgufFile::parse(&buf[..n]) else {
        sys::println(b"[GGUF] Parse error: invalid GGUF file");
        return;
    };
    Line::new(b"[GGUF] Parsed POLICY.GGF: ").num(gguf.n_tensors as u64)
        .push(b" tensors, ").num(n as u64).push(b" bytes (in infsrv)").print();
    let tests: [([f32; 4], usize); 3] = [
        ([0.8, 0.3, 0.5, 0.9], 0),
        ([0.6, 0.1, 0.5, 0.9], 1),
        ([0.1, 0.5, 0.5, 0.9], 2),
    ];
    let mut pass = 0u64;
    for (inp, expected) in &tests {
        let mut logits = [0.0f32; 3];
        if azos_ml::ggml_nano::gguf_mlp_infer(&gguf, inp, &mut logits) {
            let idx = azos_ml::ggml_nano::argmax(&logits);
            let ok = idx == *expected;
            if ok { pass += 1; }
            Line::new(if ok { b"  [OK] " } else { b"  [MISMATCH] " })
                .push(azos_ml::CLASS_NAMES[idx].as_bytes())
                .push(b" logits ").hex(logits[0].to_bits()).push(b" ")
                .hex(logits[1].to_bits()).push(b" ").hex(logits[2].to_bits()).print();
        } else {
            sys::println(b"  [MISMATCH] gguf_mlp_infer returned false");
        }
    }
    Line::new(b"[GGUF] ").num(pass).push(b"/3 tests passed").print();
}

/// The start-up checks of the model data, as the service always did them.
pub fn prepare() {
    gguf_self_test();
}

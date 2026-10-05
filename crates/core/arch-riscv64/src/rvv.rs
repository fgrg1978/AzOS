// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RISC-V Vector Extension (RVV 1.0) — float32 math kernel.
//!
//! Feature gate : `rvv`
//! QEMU target  : `make qemu-rvv`  (-cpu rv64,v=true,vlen=128,vext_spec=v1.0)
//! K1 (X60)     : VLEN=256 in hardware — see `MAX_VLEN_BYTES` below; vector
//!   context save/restore is sized for it and reads the hart's real `vlenb`
//!   at boot rather than assuming either width.
//! VisionFive 2 : NOT supported — SiFive U74 has no V extension.
//!
//! Phase 12+ will use these primitives for the embedded ML runtime.
//!
//! TODO (Phase 12): Save/restore vector registers (v0-v31, vl, vtype, vstart)
//!   on context switch.  Until then, callers must disable the timer interrupt
//!   (SIE_STIE) for the duration of any RVV operation to prevent corruption.

#![allow(dead_code)]

use core::arch::asm;

/// Read the `cycle` CSR (rdcycle) — used for benchmarking.
#[inline(always)]
pub fn rdcycle() -> u64 {
    let c: u64;
    unsafe { asm!("rdcycle {0}", out(reg) c, options(nomem, nostack)) }
    c
}

// ── Scalar reference implementations ─────────────────────────────────────────

/// Scalar f32 dot product  a · b.
pub fn dot_f32_scalar(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    let mut acc = 0.0f32;
    for i in 0..n { acc += a[i] * b[i]; }
    acc
}

/// Scalar f32 matrix multiply  C[m×n] = A[m×k] × B[k×n]  (row-major).
pub fn matmul_f32_scalar(
    c: &mut [f32], a: &[f32], b: &[f32], m: usize, k: usize, n: usize,
) {
    for i in 0..m {
        for j in 0..n {
            let mut acc = 0.0f32;
            for l in 0..k { acc += a[i*k+l] * b[l*n+j]; }
            c[i*n+j] = acc;
        }
    }
}

// ── RVV 1.0 implementations ───────────────────────────────────────────────────

/// Max K dimension for `matmul_f32_rvv` column-gather buffer (stack-allocated).
pub const MATMUL_MAX_K: usize = 64;

/// RVV 1.0 f32 dot product using LMUL=m4 (16 f32/iter at VLEN=128).
///
/// # Assembly notes
/// - `.option arch, +v, +f, +d` enables vector/float instructions locally in
///   the asm block; the Rust target (`riscv64imac-unknown-none-elf`) does not
///   include F/V at the type level, so this directive is mandatory.
/// - Result is extracted via `vse32.v` to a stack slot to avoid `freg`
///   constraints (no F extension in the Rust ABI for this target).
/// - `vfredusum.vs vd, vs2, vs1` with vd = vs1 is legal per RVV 1.0 §5.1.1.
/// - Register allocation:
///     v0:v3  — a chunk  (m4 LMUL)
///     v4:v7  — b chunk  (m4 LMUL)
///     v8:v11 — product  (m4 LMUL)
///     v16    — scalar accumulator (m1, reduction destination)
#[cfg(feature = "rvv")]
pub fn dot_f32_rvv(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    if n == 0 { return 0.0; }

    let mut result_bits: u32 = 0;
    let rp = &mut result_bits as *mut u32;
    let ap  = a.as_ptr() as usize;
    let bp  = b.as_ptr() as usize;
    let rem = n;

    unsafe {
        asm!(
            ".option arch, +v, +f, +d",
            // Initialize scalar accumulator v16 = 0.0  (bit-pattern 0x00000000)
            "vsetivli zero, 1, e32, m1, ta, ma",
            "vmv.v.i  v16, 0",

            // Main reduction loop: LMUL=m4, up to 16 f32 per iteration (VLEN=128)
            "1:",
            "beqz    {rem}, 2f",
            "vsetvli {vl}, {rem}, e32, m4, ta, ma",   // vl ← min(rem, VLMAX)
            "vle32.v v0,  ({ap})",                     // v0:v3 ← a[0..vl)
            "vle32.v v4,  ({bp})",                     // v4:v7 ← b[0..vl)
            "vfmul.vv v8, v0, v4",                     // v8:v11 ← a * b
            "vfredusum.vs v16, v8, v16",               // v16[0] += sum(v8..v11)
            "slli    {tmp}, {vl}, 2",                  // tmp ← vl * 4 bytes
            "add     {ap}, {ap}, {tmp}",
            "add     {bp}, {bp}, {tmp}",
            "sub     {rem}, {rem}, {vl}",
            "j       1b",

            // Extract scalar result to memory
            "2:",
            "vsetivli zero, 1, e32, m1, ta, ma",
            "vse32.v v16, ({rp})",

            ap  = inout(reg) ap  => _,
            bp  = inout(reg) bp  => _,
            rem = inout(reg) rem => _,
            vl  = out(reg)  _,
            tmp = out(reg)  _,
            rp  = in(reg)   rp,
        );
    }

    f32::from_bits(result_bits)
}

/// RVV 1.0 f32 matrix multiply  C[m×n] = A[m×k] × B[k×n]  (row-major).
///
/// Vectorises the K reduction via `dot_f32_rvv`.  Each B column is gathered
/// into a contiguous stack buffer before the dot product (k ≤ `MATMUL_MAX_K`).
/// A tiled / transposed-B implementation is planned for Phase 12.
#[cfg(feature = "rvv")]
pub fn matmul_f32_rvv(
    c: &mut [f32], a: &[f32], b: &[f32], m: usize, k: usize, n: usize,
) {
    let kk = k.min(MATMUL_MAX_K);
    let mut b_col = [0.0f32; MATMUL_MAX_K];
    for i in 0..m {
        for j in 0..n {
            for l in 0..kk { b_col[l] = b[l*n+j]; }
            c[i*n+j] = dot_f32_rvv(&a[i*k..(i+1)*k], &b_col[..kk]);
        }
    }
}

// ── Vector context save / restore (Phase 12) ─────────────────────────────────
//
// Each task gets a dedicated VecState slot indexed by its TID. The TID is
// read out of `Task` via `offset_of!` in `kernel/src/main.rs`'s
// `global_asm!` invocation for `context_switch_rvv.S` (the same pattern
// `task_satp_off`/`context_saving_off` already use) and passed to these
// functions as an argument — NOT read from a hand-picked byte offset into
// the task struct here. That used to be a `task_ptr.add(120)` read
// documented as "TID is a u32 at byte offset 120", which was wrong: offset
// 120 is `TaskContext.tp` (the hart id, see `CTX_TP` in
// `context_switch.S`), not `Task.tid` (offset 128, see the `offset_of!`
// assertions next to `tid` in `crates/core/sched/src/task.rs`). rvv_ctx_save /
// rvv_ctx_restore are `no_mangle extern "C"` so they can be called directly
// from context_switch_rvv.S.
//
// VecState layout — sized for MAX_VLEN_BYTES (the WIDEST vector register
// width this build supports), not the narrower width any particular board
// actually has. A hart with a narrower `vlenb` (e.g. QEMU's VLEN=128) simply
// uses a prefix of each group; a hart wider than MAX_VLEN_BYTES is refused
// at boot (see `init_vector_state`) instead of overrunning this layout —
// which is exactly what running this code's VLEN=128-sized predecessor
// under QEMU's `vlen=256` did: `vs8r.v`/`vl8r.v` move `8 * vlenb` bytes per
// instruction, so a 512-byte buffer sized for `vlenb=16` (VLEN=128) silently
// takes a `[FATAL] Kernel page fault` under `vlenb=32` (VLEN=256, the
// SpacemiT K1/X60 — and `k1` composes `rvv`, so that board hits this in
// hardware, not just in a mismatched QEMU flag). Verified by hand 2026-09-26.
//
//   offset 0                     : v0-v7   (vs8r / vl8r group 0, 8*MAX_VLEN_BYTES bytes)
//   offset 8*MAX_VLEN_BYTES      : v8-v15  (group 1)
//   offset 16*MAX_VLEN_BYTES     : v16-v23 (group 2)
//   offset 24*MAX_VLEN_BYTES     : v24-v31 (group 3)
//   offset 32*MAX_VLEN_BYTES     : vl      (u64)
//   offset 32*MAX_VLEN_BYTES+8   : vtype   (u64)
//   offset 32*MAX_VLEN_BYTES+16  : vstart  (u64)
//   offset 32*MAX_VLEN_BYTES+24  : _pad    (rounds the struct up to align(64))
//
// At MAX_VLEN_BYTES=32: 1024 + 24 = 1048 bytes core, padded to 1088 (17×64).

/// Maximum number of tasks with tracked vector state.
#[cfg(feature = "rvv")]
const MAX_VEC_TASKS: usize = 64;

/// Largest `vlenb` (bytes per vector register — CSR 0xC22) this build's
/// `VecState` is sized for. 256-bit VLEN ÷ 8 = 32 B/register: the SpacemiT
/// K1 (X60), the one board that composes `rvv` (`k1 = ["rvv", ...]`) and
/// therefore the board this bound actually has to cover. QEMU's own `rvv`
/// scenario uses VLEN=128 (vlenb=16), comfortably under this. Bump this (and
/// re-measure the `.bss` cost on `VEC_STATES` below) before enabling `rvv`
/// on hardware with a wider vector unit than the K1.
#[cfg(feature = "rvv")]
pub const MAX_VLEN_BYTES: usize = 32;

/// Bytes needed for all 32 vector registers at `MAX_VLEN_BYTES` each.
#[cfg(feature = "rvv")]
const VREGS_BYTES: usize = 32 * MAX_VLEN_BYTES;

/// `VecState`'s vregs + vl/vtype/vstart, before the `align(64)` pad — kept
/// as its own constant so the pad below is *computed*, not hand-copied, if
/// `MAX_VLEN_BYTES` ever changes.
#[cfg(feature = "rvv")]
const VEC_STATE_CORE_BYTES: usize = VREGS_BYTES + 24;

/// Padding needed to round `VEC_STATE_CORE_BYTES` up to a multiple of 64.
#[cfg(feature = "rvv")]
const VEC_STATE_PAD: usize = (64 - VEC_STATE_CORE_BYTES % 64) % 64;

/// Per-task vector register state, sized for `MAX_VLEN_BYTES` (the widest
/// `vlenb` this build supports), not for whatever `vlenb` the running hart
/// actually reports — see the layout comment above.
///
/// `.bss` cost at `MAX_VEC_TASKS` = 64: 64 × size_of::<VecState>() =
/// 64 × 1088 = 69,632 bytes (68 KiB). The VLEN=128-sized predecessor of this
/// struct cost 64 × 576 = 36,864 bytes (36 KiB) — roughly double, for
/// double the vector register width.
#[cfg(feature = "rvv")]
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct VecState {
    /// v0-v31 packed contiguously, `MAX_VLEN_BYTES` per register.
    pub vregs:  [u8; VREGS_BYTES],
    /// `vl` CSR value at save time.
    pub vl:     u64,
    /// `vtype` CSR value at save time.
    pub vtype:  u64,
    /// `vstart` CSR value at save time.
    pub vstart: u64,
    /// Padding out to a multiple of 64 (see `VEC_STATE_PAD`).
    _pad: [u8; VEC_STATE_PAD],
}

#[cfg(feature = "rvv")]
const ZERO_VEC_STATE: VecState = VecState {
    vregs: [0u8; VREGS_BYTES], vl: 0, vtype: 0, vstart: 0, _pad: [0u8; VEC_STATE_PAD],
};

#[cfg(feature = "rvv")]
static mut VEC_STATES: [VecState; MAX_VEC_TASKS] = [ZERO_VEC_STATE; MAX_VEC_TASKS];

/// The running hart's `vlenb` (bytes per vector register), once
/// `init_vector_state` has run — `0` is the "uninitialized / disabled"
/// sentinel. A real V-capable hart never reports `vlenb == 0` (VLEN >= ELEN
/// >= 32 bits per RVV 1.0), so `0` is safe to use as "no vector state save,
/// full stop": `rvv_ctx_save`/`rvv_ctx_restore` check it and no-op if unset,
/// which is what running boot on hardware `init_vector_state` refused looks
/// like — degraded (no vector context across a switch) rather than an
/// overrun, and always paired with the boot-time refusal line so it is never
/// silent in practice.
#[cfg(feature = "rvv")]
static VLEN_BYTES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Read `vlenb` (CSR 0xC22) directly from hardware — the actual bytes per
/// vector register on this hart, independent of anything this build assumes.
#[cfg(feature = "rvv")]
#[inline(always)]
pub fn read_vlenb() -> usize {
    let v: usize;
    unsafe {
        asm!(".option arch, +v", "csrr {0}, vlenb", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Boot-time vector-state sizing check. Call once, before any task can be
/// dispatched (context_switch_rvv.S calls rvv_ctx_save/rvv_ctx_restore on
/// every switch unconditionally; both no-op safely until this has run).
///
/// `Ok(vlenb)`: hardware fits `MAX_VLEN_BYTES` — vector state save/restore is
/// enabled at that `vlenb`. `Err(vlenb)`: hardware's `vlenb` (returned, even
/// though it is over budget, so the caller can print it) exceeds
/// `MAX_VLEN_BYTES`, or is `0` (no V extension) — vector state save/restore
/// stays disabled; a task's v0-v31 will not survive a context switch.
#[cfg(feature = "rvv")]
pub fn init_vector_state() -> Result<usize, usize> {
    let vlenb = read_vlenb();
    if vlenb == 0 || vlenb > MAX_VLEN_BYTES {
        VLEN_BYTES.store(0, core::sync::atomic::Ordering::SeqCst);
        Err(vlenb)
    } else {
        VLEN_BYTES.store(vlenb as u32, core::sync::atomic::Ordering::SeqCst);
        Ok(vlenb)
    }
}

/// The cached `vlenb` from `init_vector_state`, or `0` if disabled/not yet
/// called.
#[cfg(feature = "rvv")]
#[inline(always)]
fn vlen_bytes() -> usize {
    VLEN_BYTES.load(core::sync::atomic::Ordering::Relaxed) as usize
}

/// Save v0-v31 + vl/vtype/vstart for the task whose TID is `tid`.
///
/// # Safety
/// Called from `context_switch_rvv.S` with a0 = tid, loaded there from
/// `Task.tid` at `TASK_TID_OFFSET` (an `offset_of!`-derived constant, not a
/// hand-picked byte offset).
#[cfg(feature = "rvv")]
#[no_mangle]
pub unsafe extern "C" fn rvv_ctx_save(tid: u32) {
    let tid = tid as usize;
    if tid >= MAX_VEC_TASKS { return; }

    // Boot refused this hart's `vlenb`, or `init_vector_state` never ran:
    // no vector state exists to save. See `VLEN_BYTES`'s doc comment.
    let vlenb = vlen_bytes();
    if vlenb == 0 { return; }
    let stride = vlenb * 8; // bytes moved per vs8r.v (8 whole registers)

    let base = (&raw mut VEC_STATES[tid]) as *mut u8;
    let mut vl:     u64 = 0;
    let mut vtype:  u64 = 0;
    let mut vstart: u64 = 0;

    asm!(
        ".option arch, +v",
        // Save v0-v31 as four groups of 8 whole registers, strided by the
        // hart's actual vlenb*8 (NOT a hand-picked 128 — that assumed
        // VLEN=128 and overran under the K1's VLEN=256).
        // vs8r.v does not depend on vtype/vl — safe to call unconditionally.
        "vs8r.v v0,  ({b})",
        "add    {t}, {b}, {stride}",
        "vs8r.v v8,  ({t})",
        "add    {t}, {t}, {stride}",
        "vs8r.v v16, ({t})",
        "add    {t}, {t}, {stride}",
        "vs8r.v v24, ({t})",
        // Save vl / vtype / vstart CSRs.
        "csrr {vl},     vl",
        "csrr {vtype},  vtype",
        "csrr {vstart}, vstart",
        b      = in(reg)  base,
        t      = out(reg) _,
        stride = in(reg)  stride,
        vl     = out(reg) vl,
        vtype  = out(reg) vtype,
        vstart = out(reg) vstart,
    );

    (base.add(VREGS_BYTES) as *mut u64).write(vl);
    (base.add(VREGS_BYTES + 8) as *mut u64).write(vtype);
    (base.add(VREGS_BYTES + 16) as *mut u64).write(vstart);
}

/// Restore v0-v31 + vl/vtype/vstart for the task whose TID is `tid`.
///
/// # Safety
/// Called from `context_switch_rvv.S` with a0 = tid, loaded there from
/// `Task.tid` at `TASK_TID_OFFSET` (an `offset_of!`-derived constant, not a
/// hand-picked byte offset).
#[cfg(feature = "rvv")]
#[no_mangle]
pub unsafe extern "C" fn rvv_ctx_restore(tid: u32) {
    let tid = tid as usize;
    if tid >= MAX_VEC_TASKS { return; }

    // See rvv_ctx_save: no cached vlenb means boot refused this hart's
    // width, or init never ran — nothing to restore.
    let vlenb = vlen_bytes();
    if vlenb == 0 { return; }
    let stride = vlenb * 8; // bytes moved per vl8r.v (8 whole registers)

    let base   = (&raw const VEC_STATES[tid]) as *const u8;
    let vl:     u64 = (base.add(VREGS_BYTES) as *const u64).read();
    let vtype:  u64 = (base.add(VREGS_BYTES + 8) as *const u64).read();
    let vstart: u64 = (base.add(VREGS_BYTES + 16) as *const u64).read();

    asm!(
        ".option arch, +v",
        // Restore vtype and vl: vsetvl rd=x0, rs1=saved_vl, rs2=saved_vtype.
        "vsetvl zero, {vl}, {vtype}",
        // Restore v0-v31 (whole-register — independent of vtype/vl),
        // strided by the hart's actual vlenb*8 (see rvv_ctx_save).
        "vl8r.v v0,  ({b})",
        "add    {t}, {b}, {stride}",
        "vl8r.v v8,  ({t})",
        "add    {t}, {t}, {stride}",
        "vl8r.v v16, ({t})",
        "add    {t}, {t}, {stride}",
        "vl8r.v v24, ({t})",
        // Restore vstart.
        "csrw vstart, {vstart}",
        b      = in(reg) base,
        t      = out(reg) _,
        stride = in(reg) stride,
        vl     = in(reg) vl,
        vtype  = in(reg) vtype,
        vstart = in(reg) vstart,
    );
}

// ── Isolation probe (canary for the tid-vs-offset-120 bug) ───────────────────
//
// Whole-register loads/stores, independent of vl/vtype — same primitive
// rvv_ctx_save/rvv_ctx_restore use, deliberately, so the probe exercises the
// exact instructions the real save/restore path relies on rather than a
// different vector idiom that could pass for unrelated reasons.
//
// Gated on the existing `rvv` feature (not a new crate feature): the kernel
// side is gated on its own `rvv-isolation-probe` feature instead, and
// nothing there requires a matching feature to exist in this crate's own
// Cargo.toml, which is out of scope for this change. `#![allow(dead_code)]`
// at the top of this file covers these being unused in a plain `rvv` build.

/// Fill v0-v31 with `pattern`, `vlen_bytes()` bytes per register (the
/// hart's real `vlenb`, from `init_vector_state` — NOT a fixed 512-byte
/// assumption, for the same reason `rvv_ctx_save` isn't: the buffer is
/// sized for `MAX_VLEN_BYTES` (the worst case this build supports) but only
/// the first `32 * vlenb` bytes are ever touched by the vl8r.v sequence).
///
/// No-op if vector state is disabled (`vlen_bytes() == 0`) — a caller doing
/// isolation testing should not reach this on a build where boot refused
/// the hart's width in the first place.
///
/// # Safety
/// Caller must have `+v` available (the `rvv` feature implies this).
#[cfg(feature = "rvv")]
pub unsafe fn probe_fill_pattern(pattern: u8) {
    let vlenb = vlen_bytes();
    if vlenb == 0 { return; }
    let stride = vlenb * 8;

    let buf = [pattern; VREGS_BYTES];
    let base = buf.as_ptr();
    asm!(
        ".option arch, +v",
        "vl8r.v v0,  ({b})",
        "add    {t}, {b}, {stride}",
        "vl8r.v v8,  ({t})",
        "add    {t}, {t}, {stride}",
        "vl8r.v v16, ({t})",
        "add    {t}, {t}, {stride}",
        "vl8r.v v24, ({t})",
        b      = in(reg) base,
        t      = out(reg) _,
        stride = in(reg) stride,
    );
}

/// Read back v0-v31 (`vlen_bytes()` bytes per register) and return whether
/// every one of the `32 * vlenb` bytes actually written by the vs8r.v
/// sequence still equals `pattern`. Returns `true` (trivially) if vector
/// state is disabled — see `probe_fill_pattern`.
///
/// # Safety
/// Caller must have `+v` available (the `rvv` feature implies this).
#[cfg(feature = "rvv")]
pub unsafe fn probe_check_pattern(pattern: u8) -> bool {
    let vlenb = vlen_bytes();
    if vlenb == 0 { return true; }
    let stride = vlenb * 8;

    let mut buf = [0u8; VREGS_BYTES];
    let base = buf.as_mut_ptr();
    asm!(
        ".option arch, +v",
        "vs8r.v v0,  ({b})",
        "add    {t}, {b}, {stride}",
        "vs8r.v v8,  ({t})",
        "add    {t}, {t}, {stride}",
        "vs8r.v v16, ({t})",
        "add    {t}, {t}, {stride}",
        "vs8r.v v24, ({t})",
        b      = in(reg) base,
        t      = out(reg) _,
        stride = in(reg) stride,
    );
    // Only the first 32*vlenb bytes were actually written by vs8r.v above;
    // the rest of `buf` (padding out to MAX_VLEN_BYTES) is untouched zeros
    // and must not be compared against `pattern`.
    buf[..32 * vlenb].iter().all(|&byte| byte == pattern)
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

/// Benchmark scalar vs RVV dot product.
///
/// `a` and `b` must have the same length.
/// Returns `(scalar_cycles, rvv_cycles, scalar_result, rvv_result)`.
#[cfg(feature = "rvv")]
pub fn bench_dot(a: &[f32], b: &[f32]) -> (u64, u64, f32, f32) {
    let t0 = rdcycle();
    let s  = dot_f32_scalar(a, b);
    let t1 = rdcycle();
    let v  = dot_f32_rvv(a, b);
    let t2 = rdcycle();
    (t1 - t0, t2 - t1, s, v)
}

/// Benchmark scalar vs RVV matmul for an m×k×n problem.
///
/// Caller provides pre-allocated output slices `cs` and `cv` (each of length m*n).
/// Returns `(scalar_cycles, rvv_cycles)`.
#[cfg(feature = "rvv")]
pub fn bench_matmul(
    cs: &mut [f32], cv: &mut [f32],
    a: &[f32], b: &[f32], m: usize, k: usize, n: usize,
) -> (u64, u64) {
    let t0 = rdcycle();
    matmul_f32_scalar(cs, a, b, m, k, n);
    let t1 = rdcycle();
    matmul_f32_rvv(cv, a, b, m, k, n);
    let t2 = rdcycle();
    (t1 - t0, t2 - t1)
}

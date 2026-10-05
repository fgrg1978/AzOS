// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SHA-256 block function on the ARMv8 Cryptographic Extension (FEAT_SHA256:
//! `SHA256H`, `SHA256H2`, `SHA256SU0`, `SHA256SU1`), for the kernel's module
//! and image digests (wave 13). Four rounds per `SHA256H`/`SHA256H2` pair.
//!
//! It uses SIMD registers in a kernel built `aarch64-unknown-none-softfloat`,
//! so it is plain assembly (no Rust code runs in it) and the caller must own
//! the registers: the kernel calls it only through
//! `fp_lazy::with_kernel_simd`, which saves a live user FP state first, and
//! `tools/aarch64_fp_free_check.sh` names this symbol as allowed. It touches
//! only caller-saved registers (v0-v7, v16-v31; never v8-v15).
//!
//! Registers: v0 = abcd, v1 = efgh (the running state), v2/v3 = the state at
//! the start of the block, v4-v7 = the message schedule, four words each,
//! v16 = W+K, v17 = abcd before SHA256H (SHA256H2 needs it), v18-v31 =
//! K[0..56], loaded once a call; K[56..64] is loaded per block (no register
//! left for it). Wave 14: the per-block K loads were 14 of 117 instructions.

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
core::arch::global_asm!(
    r#"
    .text
    .balign 16
    .global azos_sha256_ce_blocks
    .type azos_sha256_ce_blocks, %function
// void azos_sha256_ce_blocks(u32 state[8], const u8 *data, size_t nblocks)
azos_sha256_ce_blocks:
    .arch_extension fp
    .arch_extension simd
    .arch_extension sha2
    cbz     x2, 9f
    adrp    x8, .Lazos_sha256_k
    add     x8, x8, :lo12:.Lazos_sha256_k
    ld1     {{v18.4s, v19.4s, v20.4s, v21.4s}}, [x8], #64
    ld1     {{v22.4s, v23.4s, v24.4s, v25.4s}}, [x8], #64
    ld1     {{v26.4s, v27.4s, v28.4s, v29.4s}}, [x8], #64
    ld1     {{v30.4s, v31.4s}}, [x8], #32
    ld1     {{v0.4s, v1.4s}}, [x0]
1:
    ld1     {{v4.16b, v5.16b, v6.16b, v7.16b}}, [x1], #64
    rev32   v4.16b, v4.16b
    rev32   v5.16b, v5.16b
    rev32   v6.16b, v6.16b
    rev32   v7.16b, v7.16b
    mov     v2.16b, v0.16b
    mov     v3.16b, v1.16b
    // Groups 0-11: consume W[4g..4g+3] and compute W[4g+16..4g+19] into the
    // same register. Groups 12-15: consume only. Group g's K is v(18+g)
    // for g < 14 (`k` below); x8 points at K[56..64] for groups 14, 15.
    .irp k, 18,19,20,21,22,23,24,25,26,27,28,29
    .set r0, 4 + ((\k - 18) % 4)
    .if r0 == 4
    add     v16.4s, v4.4s, v\k\().4s
    sha256su0 v4.4s, v5.4s
    .elseif r0 == 5
    add     v16.4s, v5.4s, v\k\().4s
    sha256su0 v5.4s, v6.4s
    .elseif r0 == 6
    add     v16.4s, v6.4s, v\k\().4s
    sha256su0 v6.4s, v7.4s
    .else
    add     v16.4s, v7.4s, v\k\().4s
    sha256su0 v7.4s, v4.4s
    .endif
    mov     v17.16b, v0.16b
    sha256h  q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    .if r0 == 4
    sha256su1 v4.4s, v6.4s, v7.4s
    .elseif r0 == 5
    sha256su1 v5.4s, v7.4s, v4.4s
    .elseif r0 == 6
    sha256su1 v6.4s, v4.4s, v5.4s
    .else
    sha256su1 v7.4s, v5.4s, v6.4s
    .endif
    .endr
    add     v16.4s, v4.4s, v30.4s
    mov     v17.16b, v0.16b
    sha256h  q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    add     v16.4s, v5.4s, v31.4s
    mov     v17.16b, v0.16b
    sha256h  q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    ldr     q16, [x8]
    add     v16.4s, v6.4s, v16.4s
    mov     v17.16b, v0.16b
    sha256h  q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    ldr     q16, [x8, #16]
    add     v16.4s, v7.4s, v16.4s
    mov     v17.16b, v0.16b
    sha256h  q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    add     v0.4s, v0.4s, v2.4s
    add     v1.4s, v1.4s, v3.4s
    subs    x2, x2, #1
    b.ne    1b
    st1     {{v0.4s, v1.4s}}, [x0]
9:
    ret
    .size azos_sha256_ce_blocks, . - azos_sha256_ce_blocks
    .section .rodata
    .balign 16
.Lazos_sha256_k:
    .word 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .word 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .word 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .word 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .word 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .word 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .word 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .word 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    .text
"#
);

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
extern "C" {
    fn azos_sha256_ce_blocks(state: *mut u32, data: *const u8, nblocks: usize);
}

/// Compress `blocks` (a multiple of 64 bytes) into `state` with FEAT_SHA256.
///
/// # Safety
/// The CPU implements FEAT_SHA256, and the caller owns the SIMD registers:
/// no user FP state is live in them (it was saved), and IRQs are masked so
/// nothing else on this hart can switch it back in.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn sha256_blocks(state: &mut [u32; 8], blocks: &[u8]) {
    azos_sha256_ce_blocks(state.as_mut_ptr(), blocks.as_ptr(), blocks.len() / 64);
}

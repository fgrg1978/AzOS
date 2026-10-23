// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! riscv64 (LP64 and LP64D): the return address ra, s0 to s11 and, when
//! the build has the D extension, fs0 to fs11. lxsrv is built for
//! `riscv64imac` and saves no FP register.

use super::Entry;
use core::arch::naked_asm;

/// Bytes `switch` pushes: ra and s0..s11 rounded up to 16 bytes (14 words),
/// plus fs0..fs11.
#[cfg(target_feature = "d")]
const FRAME: usize = 208;
#[cfg(not(target_feature = "d"))]
const FRAME: usize = 112;

#[cfg(target_feature = "d")]
macro_rules! fp_save {
    () => {
        concat!(
            // The assembler of a naked function does not see the D
            // extension the crate is built with; name it here.
            ".option push\n.option arch, +d\n",
            "fsd fs0, 112(sp)\nfsd fs1, 120(sp)\nfsd fs2, 128(sp)\nfsd fs3, 136(sp)\n",
            "fsd fs4, 144(sp)\nfsd fs5, 152(sp)\nfsd fs6, 160(sp)\nfsd fs7, 168(sp)\n",
            "fsd fs8, 176(sp)\nfsd fs9, 184(sp)\nfsd fs10, 192(sp)\nfsd fs11, 200(sp)\n",
            ".option pop\n",
        )
    };
}
#[cfg(target_feature = "d")]
macro_rules! fp_load {
    () => {
        concat!(
            // The assembler of a naked function does not see the D
            // extension the crate is built with; name it here.
            ".option push\n.option arch, +d\n",
            "fld fs0, 112(sp)\nfld fs1, 120(sp)\nfld fs2, 128(sp)\nfld fs3, 136(sp)\n",
            "fld fs4, 144(sp)\nfld fs5, 152(sp)\nfld fs6, 160(sp)\nfld fs7, 168(sp)\n",
            "fld fs8, 176(sp)\nfld fs9, 184(sp)\nfld fs10, 192(sp)\nfld fs11, 200(sp)\n",
            ".option pop\n",
        )
    };
}
#[cfg(not(target_feature = "d"))]
macro_rules! fp_save {
    () => {
        ""
    };
}
#[cfg(not(target_feature = "d"))]
macro_rules! fp_load {
    () => {
        ""
    };
}

/// Save the callee-saved registers on this stack, store sp in `*save`,
/// switch to `load` and pop what was saved there (see the module docs).
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn switch(save: *mut usize, load: usize, ctx: *mut u8) {
    naked_asm!(
        concat!(
            "addi sp, sp, -{frame}\n",
            "sd ra, 0(sp)\nsd s0, 8(sp)\nsd s1, 16(sp)\nsd s2, 24(sp)\n",
            "sd s3, 32(sp)\nsd s4, 40(sp)\nsd s5, 48(sp)\nsd s6, 56(sp)\n",
            "sd s7, 64(sp)\nsd s8, 72(sp)\nsd s9, 80(sp)\nsd s10, 88(sp)\nsd s11, 96(sp)\n",
            fp_save!(),
            "sd sp, 0(a0)\n",
            "mv sp, a1\n",
            "ld ra, 0(sp)\nld s0, 8(sp)\nld s1, 16(sp)\nld s2, 24(sp)\n",
            "ld s3, 32(sp)\nld s4, 40(sp)\nld s5, 48(sp)\nld s6, 56(sp)\n",
            "ld s7, 64(sp)\nld s8, 72(sp)\nld s9, 80(sp)\nld s10, 88(sp)\nld s11, 96(sp)\n",
            fp_load!(),
            "addi sp, sp, {frame}\n",
            "ret\n",
        ),
        frame = const FRAME,
    )
}

/// First code on a new stack: `s1(s2, s3)`, i.e. `entry(ctx, arg)`.
#[unsafe(naked)]
unsafe extern "C" fn trampoline() -> ! {
    naked_asm!("mv a0, s2", "mv a1, s3", "jalr s1", "unimp")
}

/// Write the first frame below `top` (16-byte aligned); returns its sp.
///
/// # Safety
///
/// `[top - FRAME, top)` must be writable and unused.
pub(super) unsafe fn prepare(top: usize, entry: Entry, ctx: *mut u8, arg: usize) -> usize {
    let sp = top - FRAME;
    let w = sp as *mut usize;
    // SAFETY: the caller hands over the frame's bytes.
    unsafe {
        for i in 0..FRAME / 8 {
            w.add(i).write(0);
        }
        w.add(0).write(trampoline as *const () as usize); // ra
        // s0 (the frame pointer) stays 0: the frame chain ends here.
        w.add(2).write(entry as usize); // s1
        w.add(3).write(ctx as usize); // s2
        w.add(4).write(arg); // s3
    }
    sp
}

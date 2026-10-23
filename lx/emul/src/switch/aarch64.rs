// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! aarch64 (AAPCS64): x19 to x28, the frame pointer x29, the link register
//! x30 and, when the build has FP registers, the low halves d8 to d15.
//! x18 is never touched: Darwin reserves it, and elsewhere it is
//! caller-saved.

use super::Entry;
use core::arch::naked_asm;

/// Bytes `switch` pushes: 12 general registers, plus 8 FP registers.
#[cfg(target_feature = "neon")]
const FRAME: usize = 160;
#[cfg(not(target_feature = "neon"))]
const FRAME: usize = 96;

#[cfg(target_feature = "neon")]
macro_rules! fp_save {
    () => {
        "stp d8, d9, [sp, #96]\nstp d10, d11, [sp, #112]\nstp d12, d13, [sp, #128]\nstp d14, d15, [sp, #144]\n"
    };
}
#[cfg(target_feature = "neon")]
macro_rules! fp_load {
    () => {
        "ldp d8, d9, [sp, #96]\nldp d10, d11, [sp, #112]\nldp d12, d13, [sp, #128]\nldp d14, d15, [sp, #144]\n"
    };
}
#[cfg(not(target_feature = "neon"))]
macro_rules! fp_save {
    () => {
        ""
    };
}
#[cfg(not(target_feature = "neon"))]
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
            "sub sp, sp, #{frame}\n",
            "stp x19, x20, [sp, #0]\n",
            "stp x21, x22, [sp, #16]\n",
            "stp x23, x24, [sp, #32]\n",
            "stp x25, x26, [sp, #48]\n",
            "stp x27, x28, [sp, #64]\n",
            "stp x29, x30, [sp, #80]\n",
            fp_save!(),
            "mov x9, sp\n",
            "str x9, [x0]\n",
            "mov sp, x1\n",
            "ldp x19, x20, [sp, #0]\n",
            "ldp x21, x22, [sp, #16]\n",
            "ldp x23, x24, [sp, #32]\n",
            "ldp x25, x26, [sp, #48]\n",
            "ldp x27, x28, [sp, #64]\n",
            "ldp x29, x30, [sp, #80]\n",
            fp_load!(),
            "add sp, sp, #{frame}\n",
            "ret\n",
        ),
        frame = const FRAME,
    )
}

/// First code on a new stack: `x19(x20, x21)`, i.e. `entry(ctx, arg)`.
#[unsafe(naked)]
unsafe extern "C" fn trampoline() -> ! {
    naked_asm!("mov x0, x20", "mov x1, x21", "blr x19", "brk #0x1")
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
        w.add(0).write(entry as usize); // x19
        w.add(1).write(ctx as usize); // x20
        w.add(2).write(arg); // x21
        // x29 stays 0: the frame chain ends here.
        w.add(11).write(trampoline as *const () as usize); // x30
    }
    sp
}

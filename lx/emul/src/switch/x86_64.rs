// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! x86_64 (System V): rbx, rbp, r12 to r15 and, when the build has SSE,
//! the MXCSR and x87 control words (callee-saved in that ABI). The return
//! address `call` pushed is the saved program counter.

use super::Entry;
use core::arch::naked_asm;

/// Words below the return address: six registers, plus one for the two
/// control words.
#[cfg(target_feature = "sse")]
const WORDS: usize = 7;
#[cfg(not(target_feature = "sse"))]
const WORDS: usize = 6;

#[cfg(target_feature = "sse")]
macro_rules! fp_save {
    () => {
        "sub rsp, 8\nstmxcsr dword ptr [rsp]\nfnstcw word ptr [rsp + 4]\n"
    };
}
#[cfg(target_feature = "sse")]
macro_rules! fp_load {
    () => {
        "ldmxcsr dword ptr [rsp]\nfldcw word ptr [rsp + 4]\nadd rsp, 8\n"
    };
}
#[cfg(not(target_feature = "sse"))]
macro_rules! fp_save {
    () => {
        ""
    };
}
#[cfg(not(target_feature = "sse"))]
macro_rules! fp_load {
    () => {
        ""
    };
}

/// Save the callee-saved registers on this stack, store rsp in `*save`,
/// switch to `load` and pop what was saved there (see the module docs).
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn switch(save: *mut usize, load: usize, ctx: *mut u8) {
    naked_asm!(concat!(
        "push rbp\npush rbx\npush r12\npush r13\npush r14\npush r15\n",
        fp_save!(),
        "mov [rdi], rsp\n",
        "mov rsp, rsi\n",
        fp_load!(),
        "pop r15\npop r14\npop r13\npop r12\npop rbx\npop rbp\n",
        "ret\n",
    ))
}

/// First code on a new stack: `r12(r13, r14)`, i.e. `entry(ctx, arg)`. The
/// `ret` that got here left rsp at the 16-byte aligned top, as a `call`
/// needs.
#[unsafe(naked)]
unsafe extern "C" fn trampoline() -> ! {
    naked_asm!("mov rdi, r13", "mov rsi, r14", "call r12", "ud2")
}

/// Write the first frame below `top` (16-byte aligned); returns its rsp.
///
/// # Safety
///
/// `[top - 8 * (WORDS + 1), top)` must be writable and unused.
pub(super) unsafe fn prepare(top: usize, entry: Entry, ctx: *mut u8, arg: usize) -> usize {
    let sp = top - 8 * (WORDS + 1);
    let w = sp as *mut usize;
    // Index of r15 (the lowest pushed register).
    let r15 = WORDS - 6;
    // SAFETY: the caller hands over the frame's bytes.
    unsafe {
        for i in 0..=WORDS {
            w.add(i).write(0);
        }
        if WORDS == 7 {
            // MXCSR 0x1f80 (all exceptions masked, round to nearest) and the
            // x87 control word 0x037f: the ABI's initial values.
            w.write(0x037f_0000_1f80);
        }
        w.add(r15 + 1).write(arg); // r14
        w.add(r15 + 2).write(ctx as usize); // r13
        w.add(r15 + 3).write(entry as usize); // r12
        // rbx and rbp stay 0: the frame chain ends here.
        w.add(WORDS).write(trampoline as *const () as usize); // return address
    }
    sp
}

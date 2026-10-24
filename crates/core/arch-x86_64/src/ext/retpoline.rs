// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The indirect-branch thunk of a kernel built with Kconfig
//! `X86_MIT_SPECTRE_V2` = probe: `-Zretpoline -Zretpoline-external-thunk`
//! (tools/build/kconfig_to_cargo.py) makes every indirect call and jump in the
//! kernel, `core` and `alloc` included, go through `__x86_indirect_thunk_r11`
//! (the kernel code model reaches only through r11), which this file defines.
//!
//! The assembled body is the retpoline: an indirect call whose speculation
//! is trapped in a `pause; lfence` loop, the target arriving by `ret`. That
//! is the state of the thunk until the boot CPU has decided, so the safe
//! path is the default. When the CPU protects indirect branches itself
//! (eIBRS, AutoIBRS), [`set_mode`] patches the body ONCE to a plain
//! `jmp *%r11`, followed by `int3`s (what Linux's alternatives do). It is
//! patched, not tested at run time: a `cmp`/`jne` in front of a `jmp *%r11`
//! would let a mispredicted branch speculate that `jmp`, which is the very
//! thing a retpoline exists to stop. The text is writable at that point:
//! `mitigations::select` runs from `cpu_features`, before `vmm::enable_paging`
//! applies W^X, on the boot CPU alone; the boot map is RWX.
//!
//! Under `n` or `require` the kernel is built without the thunk and nothing
//! references it; the bytes below are then unreferenced.

use super::mitigations::{thunk_patch, ThunkMode, THUNK_BYTES};

core::arch::global_asm!(
    ".pushsection .text.__x86_indirect_thunk_r11, \"ax\", @progbits",
    ".balign 32",
    ".globl __x86_indirect_thunk_r11",
    ".type __x86_indirect_thunk_r11, @function",
    "__x86_indirect_thunk_r11:",
    "    call 3f",
    "2:  pause",
    "    lfence",
    "    jmp 2b",
    "3:  movq %r11, (%rsp)",
    "    ret",
    // Padded to `THUNK_BYTES` (mitigations.rs) with int3.
    "    .fill {n} - (. - __x86_indirect_thunk_r11), 1, 0xcc",
    ".size __x86_indirect_thunk_r11, . - __x86_indirect_thunk_r11",
    ".popsection",
    n = const THUNK_BYTES,
    options(att_syntax),
);

unsafe extern "C" {
    static __x86_indirect_thunk_r11: u8;
}

/// Switch the thunk to `mode`; whether the bytes read back as written.
///
/// # Safety
/// Boot CPU, once, before any other CPU runs and before the kernel's tables
/// make the text read-only; nothing may be executing inside the thunk (a
/// retpoline in flight on an interrupt is not: interrupts are off).
pub unsafe fn set_mode(mode: ThunkMode) -> bool {
    let Some(new) = thunk_patch(mode) else { return true };
    let at = (&raw const __x86_indirect_thunk_r11) as *mut u8;
    for (i, &b) in new.iter().enumerate() {
        // SAFETY: the thunk's own THUNK_BYTES, writable before W^X (the caller).
        unsafe { at.add(i).write_volatile(b) };
    }
    // Self-modified code: serialise this CPU's instruction stream before the
    // first indirect call (cpuid is architecturally serialising).
    let _ = core::arch::x86_64::__cpuid(0);
    // SAFETY: as above.
    new.iter().enumerate().all(|(i, &b)| unsafe { at.add(i).read_volatile() } == b)
}

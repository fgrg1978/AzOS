// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Arm semihosting, the one call the kernel makes: `SYS_EXIT` with a status.
//!
//! QEMU's aarch64 `virt` machine has no power-off device that carries a
//! status (PSCI `SYSTEM_OFF` exits 0 whatever happened), so the ktest runner
//! leaves through semihosting when Kconfig KTEST_SEMIHOSTING_EXIT is on.
//! QEMU must run with `-semihosting-config enable=on,target=native`;
//! without it `HLT #0xF000` is an undefined instruction at EL1.

/// End the emulator with exit status `code`. Does not return; if the call
/// comes back (a host that ignores it), park with interrupts masked.
#[cfg(target_arch = "aarch64")]
pub fn exit(code: u32) -> ! {
    /// Semihosting operation `SYS_EXIT` (0x18; the Angel name, not a kernel syscall).
    const ANGEL_SYS_EXIT: u32 = 0x18;
    /// `ADP_Stopped_ApplicationExit`: the reason under which the subcode is
    /// the exit status (AArch64 takes a two-word parameter block).
    const ADP_STOPPED_APPLICATION_EXIT: u64 = 0x2_0026;
    let block: [u64; 2] = [ADP_STOPPED_APPLICATION_EXIT, code as u64];
    // SAFETY: the semihosting trap reads the two-word block at x1 (a live
    // stack array) and, with semihosting on, ends the emulator.
    unsafe {
        core::arch::asm!("msr daifset, #0xf", "hlt #0xf000",
            in("w0") ANGEL_SYS_EXIT, in("x1") block.as_ptr(), options(nostack));
    }
    loop {
        // SAFETY: parks this CPU; interrupts are masked above.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)) };
    }
}

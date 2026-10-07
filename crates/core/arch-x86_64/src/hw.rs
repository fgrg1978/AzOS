// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The few x86_64 instructions the boot-to-banner path needs (MSRs, the TSC,
//! RFLAGS, port I/O, hlt). Compiled only for x86_64; on the host the
//! contract methods that use them keep their `todo!()`.

#![cfg(target_arch = "x86_64")]

/// IA32_GS_BASE: the kernel's per-CPU base (the hart id, as on the other ISAs).
pub const IA32_GS_BASE: u32 = 0xC000_0101;
/// RFLAGS.IF.
pub const RFLAGS_IF: u64 = 1 << 9;
/// QEMU `isa-debug-exit` (`-device isa-debug-exit,iobase=0xf4,iosize=4`):
/// a write of `v` exits QEMU with status `(v << 1) | 1`. Ignored elsewhere.
pub const DEBUG_EXIT_PORT: u16 = 0xF4;

#[inline(always)]
pub fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: reading an architectural MSR at CPL0.
    unsafe { core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
    ((hi as u64) << 32) | lo as u64
}

#[inline(always)]
pub fn wrmsr(msr: u32, v: u64) {
    // SAFETY: writing an architectural MSR at CPL0.
    unsafe { core::arch::asm!("wrmsr", in("ecx") msr, in("eax") v as u32, in("edx") (v >> 32) as u32, options(nomem, nostack, preserves_flags)) };
}

#[inline(always)]
pub fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: rdtsc has no side effect.
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
    ((hi as u64) << 32) | lo as u64
}

#[inline(always)]
pub fn rflags() -> u64 {
    let f: u64;
    // SAFETY: reads RFLAGS through the stack.
    unsafe { core::arch::asm!("pushfq", "pop {}", out(reg) f, options(nomem, preserves_flags)) };
    f
}

#[inline(always)]
pub fn cli() {
    // SAFETY: masks maskable interrupts.
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
}

#[inline(always)]
pub fn sti() {
    // SAFETY: unmasks maskable interrupts.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
}

#[inline(always)]
pub fn hlt() {
    // SAFETY: waits for the next interrupt (forever with IF clear).
    unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)) };
}

#[inline(always)]
pub fn outb(port: u16, v: u8) {
    // SAFETY: a port write; callers name the device's port.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)) };
}

#[inline(always)]
pub fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: a port read; callers name the device's port.
    unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags)) };
    v
}

#[inline(always)]
pub fn outl(port: u16, v: u32) {
    // SAFETY: a port write; callers name the device's port.
    unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack, preserves_flags)) };
}

/// Stop this CPU for good: interrupts off, then hlt forever.
pub fn halt_forever() -> ! {
    loop {
        cli();
        hlt();
    }
}

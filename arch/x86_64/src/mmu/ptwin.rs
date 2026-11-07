// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! PT_PROTECTION on x86_64: the kernel half's page-table pool carries
//! supervisor protection key [`PKEY`], `IA32_PKRS` denies writes to it, and
//! `pt_set` lifts the denial for the one store (Kconfig `X86_PKS`).
//!
//! `CR4.PKS` makes the CPU check every supervisor access to a supervisor page
//! (U/S = 0 at every level) against `IA32_PKRS` by the key in PTE bits 62:59.
//! The CPU's own accessed/dirty updates of a walk are not checked, so the
//! tables stay live. The window is a WRMSR before the store and one after, with
//! interrupts off between; it restores what it found, so a window opened in a
//! window (a fault path under `pt_set`) closes to the outer state.

/// The key the pool carries. Key 0 is every other kernel page.
pub const PKEY: u64 = 1;
/// First bit of the key field of a leaf.
pub const PTE_PKEY_SHIFT: u32 = 59;
/// The key field of a leaf (bits 62:59).
pub const PTE_PKEY_MASK: u64 = 0xF << PTE_PKEY_SHIFT;
/// `IA32_PKRS` (SDM Vol. 4): two bits a key, AD then WD.
pub const IA32_PKRS: u32 = 0x6E1;
/// `CR4.PKS` (bit 24).
pub const CR4_PKS: u64 = 1 << 24;
/// The access-disable bit of [`PKEY`] in PKRS.
pub const PKRS_AD: u64 = 1 << (2 * PKEY);
/// The write-disable bit of [`PKEY`] in PKRS.
pub const PKRS_WD: u64 = 2 << (2 * PKEY);
/// `IA32_PKRS` while the pool is locked: reads of the key allowed, writes denied.
pub const PKRS_LOCKED: u64 = PKRS_WD;
#[cfg(target_arch = "x86_64")]
const RFLAGS_IF: u64 = 1 << 9;

/// The key bits a pool leaf carries.
pub const fn key_bits() -> u64 {
    PKEY << PTE_PKEY_SHIFT
}

/// The leaf `word` tagged with the pool's key (any other key cleared).
pub const fn tag(word: u64) -> u64 {
    (word & !PTE_PKEY_MASK) | key_bits()
}

/// The PKRS value of an open window over `pkrs`: [`PKEY`]'s write-deny lifted,
/// every other key as it was.
pub const fn opened(pkrs: u64) -> u64 {
    pkrs & !PKRS_WD
}

/// What a window open returns: the PKRS found (a 32-bit register) and whether
/// interrupts were on, for the close.
pub const fn pack(pkrs: u64, interrupts_on: bool) -> u64 {
    (pkrs & 0xFFFF_FFFF) | (interrupts_on as u64) << 32
}

/// The token of a shut: the PKRS found, and no interrupt flag to restore.
pub const fn shut_token(pkrs: u64) -> u64 {
    pack(pkrs, false)
}

/// Inverse of [`pack`].
pub const fn unpack(token: u64) -> (u64, bool) {
    (token & 0xFFFF_FFFF, token >> 32 != 0)
}

/// `CR4.PKS` on and PKRS denying writes to the pool, on this CPU. Only after
/// `ArchPlatform::pt_key_present` said yes; the caller has run
/// `setup_paging_regs` (`CR0.WP`). Whether PKRS took is read back.
#[cfg(target_arch = "x86_64")]
pub fn lock_this_cpu() -> bool {
    let cr4: u64;
    // SAFETY: CPL 0; the caller saw CPUID report PKS, so CR4.PKS and
    // IA32_PKRS exist. PKRS is written before any pool page is written again.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov cr4, {}", in(reg) cr4 | CR4_PKS, options(nostack, preserves_flags));
    }
    super::cpu::wrmsr(IA32_PKRS, PKRS_LOCKED);
    super::cpu::rdmsr(IA32_PKRS) == PKRS_LOCKED
}

/// Is this CPU denying writes to the pool now?
#[cfg(target_arch = "x86_64")]
pub fn locked_this_cpu() -> bool {
    let cr4: u64;
    // SAFETY: reads CR4.
    unsafe { core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags)) };
    cr4 & CR4_PKS != 0 && super::cpu::rdmsr(IA32_PKRS) == PKRS_LOCKED
}

/// Interrupts off, [`PKEY`]'s write-deny lifted; the token for [`close`].
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn open() -> u64 {
    let flags: u64;
    // SAFETY: reads RFLAGS and clears IF; `close` puts IF back as found.
    unsafe { core::arch::asm!("pushfq", "pop {}", "cli", out(reg) flags, options(preserves_flags)) };
    let pkrs = super::cpu::rdmsr(IA32_PKRS);
    super::cpu::wrmsr(IA32_PKRS, opened(pkrs));
    pack(pkrs, flags & RFLAGS_IF != 0)
}

/// Deny writes to the pool's key whatever a window below had opened (an NMI or
/// #MC inside one); the token for [`close`] gives back what was found.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn shut() -> u64 {
    let pkrs = super::cpu::rdmsr(IA32_PKRS);
    super::cpu::wrmsr(IA32_PKRS, PKRS_LOCKED);
    shut_token(pkrs)
}

/// Restore PKRS and the interrupt flag a window found.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn close(token: u64) {
    let (pkrs, on) = unpack(token);
    super::cpu::wrmsr(IA32_PKRS, pkrs);
    if on {
        // SAFETY: IF was set when `open` cleared it.
        unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 [`SpinWait`]: `PAUSE` for `cpu_relax` and `LOCK CMPXCHG` for the
//! CAS (both the trait's provided bodies: `core::hint::spin_loop` and
//! `compare_exchange` compile to exactly these on x86_64, a baseline with
//! no extension to choose), and WAITPKG `UMONITOR`/`UMWAIT` for the wait
//! hint (Kconfig X86_WAITPKG; fallback: one `PAUSE`).
//!
//! UMWAIT in ring 0: the instruction executes at any CPL (CR4.TSD only
//! restricts CPL > 0) and IA32_UMWAIT_CONTROL, when the firmware or a
//! hypervisor sets it, only caps the wait further. Each step carries its
//! own TSC deadline (Kconfig X86_UMWAIT_TSC_TICKS), so a step is bounded
//! even when nobody stores to the line. Probe: CPUID.(7,0):ECX[5]; a wrong
//! claim (the `spin-ext-claim` canary under QEMU TCG, which has no
//! WAITPKG) is a #UD at the first contended wait after [`select`].
//!
//! On a host build of this crate (the `stub` facade on another ISA) the
//! WAITPKG path is compiled out and every method is the trait's default.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use azos_arch_api::isa::{x86_64 as policy, ExtPolicy};
use azos_arch_api::SpinWait;

/// The probe's verdict (`probe` only; `n`/`require` never read it).
static WAITPKG_ON: AtomicBool = AtomicBool::new(false);

/// UMONITOR/UMWAIT in use on this boot: a constant under `n`/`require`.
#[inline(always)]
pub fn waitpkg_on() -> bool {
    match policy::WAITPKG {
        ExtPolicy::Never => false,
        ExtPolicy::Require => true,
        ExtPolicy::Probe => WAITPKG_ON.load(Ordering::Relaxed),
    }
}

/// Boot, the BSP, before the APs: `waitpkg` is CPUID's answer (or a
/// canary's forced claim). Returns what the wait paths use.
pub fn select(waitpkg: bool) -> bool {
    WAITPKG_ON.store(policy::WAITPKG.gate(waitpkg), Ordering::Relaxed);
    waitpkg_on()
}

/// UMWAIT's ECX[0]: 1 = C0.1 (fast wake), 0 = C0.2 (Kconfig X86_UMWAIT_C02).
#[cfg(target_arch = "x86_64")]
const UMWAIT_STATE: u32 = if azos_limits::X86_UMWAIT_C02 { 0 } else { 1 };
/// TSC ticks per UMWAIT step (Kconfig X86_UMWAIT_TSC_TICKS).
#[cfg(target_arch = "x86_64")]
const UMWAIT_TICKS: u64 = azos_limits::X86_UMWAIT_TSC_TICKS as u64;

/// Arm the monitor on the word, re-read it (a store between the caller's
/// read and UMONITOR would otherwise be missed), and sleep until a store to
/// the line, an interrupt, or the deadline.
#[cfg(target_arch = "x86_64")]
macro_rules! umwait_step {
    ($load:literal, $a:expr, $expected:expr) => {{
        // SAFETY: `$a` is a valid, aligned word; only reached when WAITPKG
        // is in use (`waitpkg_on`). RAX/RDX and the flags are clobbered.
        unsafe {
            core::arch::asm!(
                "umonitor {addr}",
                $load,
                "jne 2f",
                "rdtsc",
                "shl rdx, 32",
                "or rax, rdx",
                "add rax, {ticks}",
                "mov rdx, rax",
                "shr rdx, 32",
                "umwait {state:e}",
                "2:",
                addr = in(reg) $a,
                e = in(reg) $expected,
                ticks = in(reg) UMWAIT_TICKS,
                state = in(reg) UMWAIT_STATE,
                t = out(reg) _,
                out("rax") _,
                out("rdx") _,
                options(nostack),
            );
        }
    }};
}

impl SpinWait for crate::X86_64 {
    /// `XCHG` (locked by definition) and `jnz` to a `call
    /// azos_spin_tas_tramp32` placed after the function. The trampoline
    /// saves every caller-saved register, so the site clobbers only the
    /// swap's register and the flags.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    #[inline(always)]
    fn tas_acquire32(&self, a: &AtomicU32) {
        // SAFETY: `a` is a valid, aligned atomic word. The trampoline
        // preserves every register and pops its argument; `push`/`call` use
        // the stack, which the asm is allowed to (no `nostack`; the kernel
        // has no red zone).
        unsafe {
            core::arch::asm!(
                "mov {t:e}, 1",
                "xchg dword ptr [{addr}], {t:e}",
                "test {t:e}, {t:e}",
                "jnz 3f",
                "2:",
                ".subsection 1",
                "3: push {addr}",
                "call azos_spin_tas_tramp32",
                "jmp 2b",
                ".subsection 0",
                addr = in(reg) a.as_ptr(),
                t = out(reg) _,
            );
        }
    }

    #[inline(always)]
    fn wait_hint32(&self, a: &AtomicU32, expected: u32) {
        #[cfg(target_arch = "x86_64")]
        if waitpkg_on() {
            umwait_step!("mov {t:e}, dword ptr [{addr}]\n cmp {t:e}, {e:e}", a.as_ptr(), expected);
            return;
        }
        let _ = (a, expected);
        self.cpu_relax();
    }

    #[inline(always)]
    fn wait_hint64(&self, a: &AtomicU64, expected: u64) {
        #[cfg(target_arch = "x86_64")]
        if waitpkg_on() {
            umwait_step!("mov {t}, qword ptr [{addr}]\n cmp {t}, {e}", a.as_ptr(), expected);
            return;
        }
        let _ = (a, expected);
        self.cpu_relax();
    }
}

/// [`SpinWait::tas_acquire32`]'s contended half for this ISA, called by the
/// trampoline below with the word in rdi.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[no_mangle]
extern "C" fn azos_spin_tas_slow32(a: &AtomicU32) {
    azos_arch_api::spin::tas_slow32(&crate::X86_64_ARCH, a)
}

// `azos_spin_tas_tramp32`: entered by `push <word>; call`; saves rax, rcx,
// rdx, rsi, rdi, r8-r11 (every caller-saved integer register; kernel code
// uses no SSE), calls `azos_spin_tas_slow32(word)`, restores them and
// returns popping the word (`ret 8`). The site's rsp is 16-aligned: the
// push, the return address and nine saves leave it 16-aligned again, minus
// the 8 the `sub` adds.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
core::arch::global_asm!(
    ".pushsection .text.azos_spin_tas_tramp32, \"ax\"",
    ".globl azos_spin_tas_tramp32",
    ".p2align 4",
    "azos_spin_tas_tramp32:",
    "    push rax",
    "    push rcx",
    "    push rdx",
    "    push rsi",
    "    push rdi",
    "    push r8",
    "    push r9",
    "    push r10",
    "    push r11",
    "    mov rdi, [rsp + 80]",
    "    sub rsp, 8",
    "    call azos_spin_tas_slow32",
    "    add rsp, 8",
    "    pop r11",
    "    pop r10",
    "    pop r9",
    "    pop r8",
    "    pop rdi",
    "    pop rsi",
    "    pop rdx",
    "    pop rcx",
    "    pop rax",
    "    ret 8",
    ".popsection",
);

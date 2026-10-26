// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The hypervisor instructions (bare-metal x86_64 only): `EFER.SVME` and
//! `VM_HSAVE_PA`, and the `VMRUN` stub.
//!
//! Every function acts on the CPU it runs on. `svm_enable_this_cpu` /
//! `svm_disable_this_cpu` are the per-CPU switch: the guest entry
//! ([`Hw`], the CPU `Hypervisor::enter` runs on) turns SVM on the first time a
//! CPU runs a guest and leaves it on, with interrupts off from the check to
//! the `VMRUN` and the thread verified to still be on the CPU it prepared for.
//! The ktest that drives `VMRUN` by hand (`kernel/src/entry/x86_64/ext/hv.rs`)
//! turns it off again when it is done.
//!
//! The host's FP/SIMD state is not saved: a guest's `VMRUN` does not switch
//! it, but the kernel is soft-float and a kernel thread (the vCPU's) holds no
//! live FP state (`fp.rs`: ring 3's state is saved at the switch to it and
//! restored on the way back to ring 3). The *guest's* state is: loaded from the
//! vCPU's XSAVE area under the host's `XCR0` right before the guest's `XCR0`
//! goes in, and saved right after the host's comes back ([`Hw`]'s `vmrun`).
//! Debug registers and the APIC are not touched; those are the monitor's, one
//! level up.

use core::arch::{asm, global_asm};

use super::probe::{EFER_SVME, MSR_VM_HSAVE_PA};
use super::svm::GuestRegs;
use crate::cpu::{rdmsr, wrmsr, IA32_EFER};

// ── SVM ─────────────────────────────────────────────────────────────────

/// Is `EFER.SVME` set on this CPU?
pub fn svm_enabled_this_cpu() -> bool {
    rdmsr(IA32_EFER) & EFER_SVME != 0
}

/// Enable SVM on this CPU: `EFER.SVME`, and `hsave_pa` (a zeroed,
/// page-aligned physical page) as the area `VMRUN` saves the host state in.
/// The probe has said SVM is usable (firmware did not set `VM_CR.SVMDIS`):
/// with it set this write would #GP.
pub fn svm_enable_this_cpu(hsave_pa: u64) {
    wrmsr(IA32_EFER, rdmsr(IA32_EFER) | EFER_SVME);
    wrmsr(MSR_VM_HSAVE_PA, hsave_pa);
}

/// Disable SVM on this CPU (no guest may be running).
pub fn svm_disable_this_cpu() {
    wrmsr(MSR_VM_HSAVE_PA, 0);
    wrmsr(IA32_EFER, rdmsr(IA32_EFER) & !EFER_SVME);
}

// `azos_svm_run(guest_vmcb_pa: rdi, host_save_pa: rsi, regs: rdx)`.
//
// The host's FS/GS/TR/LDTR/KernelGSBase and the syscall MSRs are not in the
// state `VMRUN` saves: they go out with `VMSAVE` to the host save page and
// come back with `VMLOAD` after the exit, with the guest's own `VMLOAD`ed
// before entry and `VMSAVE`d after. The caller holds GIF clear (`clgi`) for
// the whole sequence, so no interrupt or NMI runs on the guest's GS base.
// After the exit the host's RSP is back (VMRUN restores it), which is why the
// three arguments live on the stack: no register survives the guest.
//
// Offsets into GuestRegs are the field order (`svm::GuestRegs`, pinned by a
// host test): rbx 0, rcx 8, rdx 16, rsi 24, rdi 32, rbp 40, r8 48 .. r15 104.
global_asm!(
    ".section .text.azos_svm_run,\"ax\",@progbits",
    ".global azos_svm_run",
    ".type azos_svm_run,@function",
    "azos_svm_run:",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "push rdx",
    "push rsi",
    "push rdi",
    "mov rax, rsi",
    "vmsave rax",
    "mov rax, [rsp]",
    "vmload rax",
    "mov rax, [rsp + 16]",
    "mov rbx, [rax + 0]",
    "mov rcx, [rax + 8]",
    "mov rdx, [rax + 16]",
    "mov rsi, [rax + 24]",
    "mov rdi, [rax + 32]",
    "mov rbp, [rax + 40]",
    "mov r8,  [rax + 48]",
    "mov r9,  [rax + 56]",
    "mov r10, [rax + 64]",
    "mov r11, [rax + 72]",
    "mov r12, [rax + 80]",
    "mov r13, [rax + 88]",
    "mov r14, [rax + 96]",
    "mov r15, [rax + 104]",
    "mov rax, [rsp]",
    "vmrun rax",
    "mov rax, [rsp + 16]",
    "mov [rax + 0], rbx",
    "mov [rax + 8], rcx",
    "mov [rax + 16], rdx",
    "mov [rax + 24], rsi",
    "mov [rax + 32], rdi",
    "mov [rax + 40], rbp",
    "mov [rax + 48], r8",
    "mov [rax + 56], r9",
    "mov [rax + 64], r10",
    "mov [rax + 72], r11",
    "mov [rax + 80], r12",
    "mov [rax + 88], r13",
    "mov [rax + 96], r14",
    "mov [rax + 104], r15",
    "mov rax, [rsp]",
    "vmsave rax",
    "mov rax, [rsp + 8]",
    "vmload rax",
    "add rsp, 24",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "ret",
    ".size azos_svm_run, . - azos_svm_run",
);

unsafe extern "C" {
    fn azos_svm_run(guest_vmcb_pa: u64, host_save_pa: u64, regs: *mut GuestRegs);
}

/// Enter the guest described by the VMCB at `guest_vmcb_pa` and return when
/// it exits; the exit code and information are then in that VMCB
/// (`svm::off::EXIT_CODE`, ...), the guest's general registers in `regs`.
/// `host_save_pa` is a page the host's FS/GS/TR state is parked in.
///
/// # Safety
/// SVM is enabled on this CPU ([`svm_enable_this_cpu`]); `guest_vmcb_pa` and
/// `host_save_pa` are physical addresses of distinct, page-aligned, owned
/// pages (the first a VMCB that passes `Vmcb::check` with every nested page
/// table it names alive); the caller does not migrate to another CPU, and
/// saves and restores the host's FP/SIMD state around the call.
pub unsafe fn svm_run(guest_vmcb_pa: u64, host_save_pa: u64, regs: &mut GuestRegs) {
    // SAFETY: GIF is held clear across the stub so no interrupt handler runs on
    // the guest's GS base; the rest is the caller's contract.
    unsafe {
        asm!("clgi", options(nostack));
        azos_svm_run(guest_vmcb_pa, host_save_pa, regs);
        asm!("stgi", options(nostack));
    }
}

// ── the machine the entry runs on ───────────────────────────────────────

use core::sync::atomic::{AtomicU64, Ordering};

use super::cpuid::Leaf;
use super::probe::{self, SvmCaps};
use super::vcpu::{Claim, Machine, Ran, VcpuMem, VmHost};
use crate::cpu::{self, RFLAGS_IF};
use crate::mmu::{DIRECT_MAP_BASE, DIRECT_MAP_BYTES};

/// Per CPU: the page `VM_HSAVE_PA` names, 0 until the CPU first runs a guest.
static HSAVE: [AtomicU64; azos_limits::NR_CPUS] = [const { AtomicU64::new(0) }; azos_limits::NR_CPUS];

/// `CPUID.8000000A`, decoded once.
static CAPS: AtomicU64 = AtomicU64::new(u64::MAX);

/// The CPU `Hypervisor::enter` runs on; the host gives it the page its
/// `VM_HSAVE_PA` names the first time a CPU runs a guest.
pub struct Hw<'a>(pub &'a dyn VmHost);

fn xsetbv(xcr0: u64) {
    // SAFETY: CPL 0 with CR4.OSXSAVE set (`fp::init_cpu`); `xcr0` is the
    // host's own mask or a guest value `cpuid::xcr0_valid` accepted, which the
    // host's CPUID clamp limits to the host's mask.
    unsafe {
        asm!("xsetbv", in("ecx") 0u32, in("eax") xcr0 as u32, in("edx") (xcr0 >> 32) as u32,
            options(nomem, nostack, preserves_flags));
    }
}

impl Hw<'_> {
    /// Interrupts off on a CPU where SVM is on. The CPU's host-save page is
    /// allocated with interrupts on (and the check repeated: the thread may
    /// have moved), so the allocator never runs with them off.
    fn irqs_off_with_svm(&self) -> Option<u64> {
        for _ in 0..4 {
            let flags = cpu::rflags();
            cpu::cli();
            let me = cpu::percpu_id() % HSAVE.len();
            if svm_enabled_this_cpu() {
                return Some(flags);
            }
            let pa = HSAVE[me].load(Ordering::Acquire);
            if pa != 0 {
                svm_enable_this_cpu(pa);
                return Some(flags);
            }
            if flags & RFLAGS_IF != 0 {
                cpu::sti();
            }
            let pa = self.0.alloc_pages(1)?;
            if HSAVE[me].compare_exchange(0, pa, Ordering::AcqRel, Ordering::Acquire).is_err() {
                self.0.free_pages(pa, 1);
            }
        }
        None
    }
}

impl Machine for Hw<'_> {
    fn cpu(&self) -> usize {
        // percpu-hint: the caller re-checks it after `cli` (vmrun returns Ran::Moved when the thread moved)
        cpu::percpu_id()
    }

    fn host_tsc(&self) -> u64 {
        cpu::rdtsc()
    }

    fn ticks_to_tsc(&self, ticks: u64) -> u64 {
        // A span: the absolute conversion of the clock's base plus `ticks`,
        // less that of the base.
        let (base_tsc, base_ticks, _) = crate::timer::counter_scale();
        crate::timer::ticks_to_tsc(base_ticks.saturating_add(ticks)).wrapping_sub(base_tsc)
    }

    /// The host's words, with the XSAVE components the guest may enable cut to
    /// the ones the kernel's own `XCR0` holds: the guest's FP area is the size
    /// of the host's.
    fn host_cpuid(&self, leaf: u32, sub: u32) -> Leaf {
        let (eax, ebx, ecx, edx) = crate::platform_impl::cpuid(leaf, sub);
        if leaf == 0xD && sub == 0 {
            let mask = crate::fp::xcr0();
            return Leaf { eax: eax & mask as u32, ebx, ecx, edx: edx & (mask >> 32) as u32 };
        }
        Leaf { eax, ebx, ecx, edx }
    }

    fn svm_caps(&self) -> SvmCaps {
        let c = CAPS.load(Ordering::Relaxed);
        if c != u64::MAX {
            return SvmCaps { nasid: c as u32, nrips: c >> 32 & 1 != 0, flush_by_asid: c >> 33 & 1 != 0, ..SvmCaps::default() };
        }
        let caps = probe::svm_caps_now();
        CAPS.store(caps.nasid as u64 | (caps.nrips as u64) << 32 | (caps.flush_by_asid as u64) << 33, Ordering::Relaxed);
        caps
    }

    fn fp_bytes(&self) -> usize {
        crate::fp::area_bytes()
    }

    fn read_phys(&self, pa: u64, buf: &mut [u8]) -> bool {
        let Some(end) = pa.checked_add(buf.len() as u64) else { return false };
        if end > DIRECT_MAP_BYTES {
            return false;
        }
        // SAFETY: inside the direct map, which maps RAM; the caller names a
        // frame of a guest or of its nested tables.
        unsafe { core::ptr::copy_nonoverlapping((pa + DIRECT_MAP_BASE) as *const u8, buf.as_mut_ptr(), buf.len()) };
        true
    }

    fn map(&self, pa: u64) -> *mut u8 {
        (pa + DIRECT_MAP_BASE) as *mut u8
    }

    /// `cli`; guest FP state in; the guest's `XCR0`; `VMRUN`; the host's `XCR0`;
    /// guest FP state out; the interrupt flag back (a host interrupt that
    /// ended the entry is taken here).
    fn vmrun(&mut self, v: &mut VcpuMem, fp: *mut u8, guest_xcr0: u64, cpu: usize, claim: &Claim) -> Ran {
        let Some(flags) = self.irqs_off_with_svm() else { return Ran::NoSvm };
        // percpu-hint: compared after `cli` (irqs_off_with_svm): a move is Ran::Moved
        if cpu::percpu_id() != cpu {
            if flags & RFLAGS_IF != 0 {
                cpu::sti();
            }
            return Ran::Moved;
        }
        let host_xcr0 = crate::fp::xcr0();
        let (vmcb_pa, save_pa) = (v.vmcb_pa(), v.host_save_pa());
        // SAFETY: interrupts are off on a CPU with SVM enabled; `fp` is the
        // vCPU's own area of `fp::area_bytes()` bytes, 64-aligned (it follows
        // the page-aligned `VcpuMem`), holding `init_area`'s image or a state
        // saved here; both pages are owned and distinct; the thread does not
        // migrate with interrupts off.
        unsafe {
            crate::fp::restore_eager(fp);
            if guest_xcr0 != host_xcr0 {
                xsetbv(guest_xcr0);
            }
            claim.enter(v, cpu);
            svm_run(vmcb_pa, save_pa, &mut v.run.regs);
            claim.leave(cpu);
            if guest_xcr0 != host_xcr0 {
                xsetbv(host_xcr0);
            }
            crate::fp::save_eager(fp);
        }
        if flags & RFLAGS_IF != 0 {
            cpu::sti();
        }
        Ran::Done
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 per-CPU tables: the GS-relative areas (`X86_64_PERCPU`), each
//! CPU's GDT and TSS (inside its area), the IST stacks, the shared IDT,
//! and the `syscall` MSRs. [`init_cpu`] runs once per CPU: the boot CPU
//! from `trap_init` (before the banner), a secondary from its bring-up
//! path before it enables interrupts.
//!
//! **Stacks.** Each CPU's interrupt stack (`INTERRUPT_STACK_SIZE_KB`,
//! `AZOS_IRQ_STACK_BASE[cpu]`) is split: the top three
//! `X86_IST_STACK_SIZE_KB` slices are the IST stacks of #DF, NMI and #MC;
//! below them, device interrupt handlers run, switched to in software by
//! `trap_entry.S` exactly as on riscv64 and aarch64. The magic word at the
//! base still catches an overflow of the handler stack.
//!
//! **IST top word.** The 16 bytes above each IST stack's initial RSP hold
//! this CPU's `PerCpu` address: the IST entry path (`ist_common` in
//! `trap_entry.S`) cannot trust GS (an NMI can land between `syscall` and
//! its `swapgs`), so it saves the live GS base, loads this one, and puts
//! the saved one back on the way out (Linux's paranoid entry).

use core::cell::UnsafeCell;

use azos_arch::cpu::{self, PerCpu};
use azos_arch::{gdt, idt};

use crate::{IRQ_STACK_SIZE, MAX_HARTS};

/// One IST stack, bytes (Kconfig `X86_IST_STACK_SIZE_KB`).
pub(crate) const IST_STACK_SIZE: usize = azos_limits::X86_IST_STACK_SIZE_KB * 1024;
/// The IST slices carved from the top of the interrupt stack.
pub(crate) const IST_TOTAL: usize = IST_STACK_SIZE * idt::IST_USED;
/// What is left below them for device interrupt handlers.
pub(crate) const IRQ_HANDLER_STACK: usize = IRQ_STACK_SIZE - IST_TOTAL;
/// Bytes reserved above each IST stack's initial RSP (the `PerCpu` address
/// and a pad word, keeping the RSP 16-byte aligned).
pub(crate) const IST_TOP_RESERVED: usize = 16;

const _: () = assert!(
    IRQ_HANDLER_STACK >= 4096,
    "INTERRUPT_STACK_SIZE_KB must leave at least 4 KiB below the three X86_IST_STACK_SIZE_KB stacks",
);
const _: () = assert!(IST_STACK_SIZE % 16 == 0 && IRQ_STACK_SIZE % 16 == 0);

/// The per-CPU areas; `IA32_GS_BASE` points at this CPU's element.
/// `boot.S` points the boot CPU's GS at element 0 before Rust runs.
#[repr(transparent)]
pub struct PerCpuAreas(pub [UnsafeCell<PerCpu>; MAX_HARTS]);
// SAFETY: each element is written only by its own CPU (init, the entry asm
// through GS) once that CPU runs; the boot CPU writes element `cpu` before
// starting CPU `cpu`.
unsafe impl Sync for PerCpuAreas {}

#[unsafe(no_mangle)]
pub static X86_64_PERCPU: PerCpuAreas = PerCpuAreas([const { UnsafeCell::new(PerCpu::new()) }; MAX_HARTS]);

/// Set (to 1) by whoever sets CR4.SMAP on the boot CPU, before interrupts
/// are enabled: from then on every trap entry runs `clac` (`trap_entry.S`).
#[unsafe(no_mangle)]
pub static X86_64_SMAP_ON: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// The IDT every CPU loads (`[low, high]` quadwords per vector).
struct Idt(UnsafeCell<[[u64; 2]; idt::VECTORS]>);
// SAFETY: written once by the boot CPU in `init_cpu(0)`, before any other
// CPU runs; read only by the CPUs (`lidt`) afterwards.
unsafe impl Sync for Idt {}
static IDT: Idt = Idt(UnsafeCell::new([[0; 2]; idt::VECTORS]));

unsafe extern "C" {
    /// The 256 entry stubs (`trap_entry.S`), one address per vector.
    static x86_64_vector_stubs: [u64; idt::VECTORS];
    /// The `IA32_LSTAR` target (`trap_entry.S`).
    fn syscall_entry();
}

/// Fill the shared IDT from the stub table: every vector an interrupt gate
/// through the kernel code selector, #DF/NMI/#MC on their IST stacks,
/// `int3`/`into` reachable from ring 3.
fn build_idt() {
    // SAFETY: boot CPU only, before any other CPU loads the table.
    let table = unsafe { &mut *IDT.0.get() };
    for (v, entry) in table.iter_mut().enumerate() {
        // SAFETY: the stub table is 256 initialised addresses in .rodata.
        let stub = unsafe { (&raw const x86_64_vector_stubs).cast::<u64>().add(v).read() };
        *entry = idt::kernel_gate(v, stub, gdt::KERNEL_CS);
    }
}

/// Bring up CPU `cpu`'s tables: GS base, GDT + TSS (RSP0 later, IST now),
/// the IDT (built by CPU 0), the `syscall` MSRs, and the FP/SIMD state
/// ring 3 will use. `AZOS_IRQ_STACK_BASE[cpu]` must be armed.
pub fn init_cpu(cpu: usize) {
    assert!(cpu < MAX_HARTS, "x86_64: CPU {cpu} >= NR_CPUS");
    let irq_base = crate::boot::irq_stack_base(cpu);
    assert!(irq_base != 0, "x86_64: CPU {cpu} has no interrupt stack for its IST slices");
    let area = X86_64_PERCPU.0[cpu].get();

    // SAFETY: this CPU's own area, not yet loaded into any descriptor
    // register; nothing else touches it.
    unsafe {
        let top = irq_base + IRQ_STACK_SIZE;
        for k in 0..idt::IST_USED {
            let slot_top = top - k * IST_STACK_SIZE;
            let rsp = slot_top - IST_TOP_RESERVED;
            // The paranoid entry's GS: [rsp] = PerCpu address, [rsp+8] = 0.
            (rsp as *mut u64).write_volatile(area as u64);
            ((rsp + 8) as *mut u64).write_volatile(0);
            // IST index k+1 (1 = #DF, 2 = NMI, 3 = #MC, `idt::ist_for`).
            (*area).tss.ist[k] = rsp as u64;
        }
        let tss_base = (&raw const (*area).tss) as u64;
        (*area).gdt = gdt::table(tss_base);
    }

    cpu::set_percpu(cpu);
    if cpu == 0 {
        build_idt();
    }
    // SAFETY: the GDT is in this CPU's static area and never moves; its
    // layout is `gdt::table`'s. The IDT is static and complete.
    unsafe {
        cpu::load_gdt_and_tss(&raw const (*area).gdt);
        cpu::load_idt(IDT.0.get());
    }
    // `ltr` and the far return leave GS alone, but reassert the base: the
    // trap entry depends on it from the first interrupt on.
    cpu::set_percpu(cpu);
    cpu::enable_syscall(syscall_entry as *const () as u64);
    super::fp::init_cpu(cpu);
}

/// The boot CPU's half of `ArchEntry::trap_init`: arm its interrupt stack
/// (the static `boot_irq_stack`, as riscv64's `irq_stacks_arm` does), then
/// [`init_cpu`]. Interrupts stay masked; nothing is routed yet.
pub fn init_boot_cpu() {
    crate::boot::arm_irq_stack(0, crate::boot::boot_irq_stack_base());
    init_cpu(0);
}

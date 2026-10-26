// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The VMX instructions (bare-metal x86_64 only): `VMXON` per CPU, the
//! VMCS accessors, `VMLAUNCH` / `VMRESUME` with the guest's registers, and
//! the [`Machine`] the shared guest entry runs on Intel.
//!
//! Everything that decides anything is pure and lives in [`super::vmx`]; this
//! file is the instructions and the order they must come in, which only
//! hardware can check (QEMU's TCG has no VMX, so the host tests do not
//! exercise it).
//!
//! # VMX operation
//!
//! A CPU enters VMX operation the first time it runs a guest (`CR4.VMXE`, the
//! firmware lock bits of `IA32_FEATURE_CONTROL` set if firmware left them
//! open, `VMXON` on a per-CPU region) and stays there: like `EFER.SVME` on the
//! AMD side, no code outside a guest run depends on the CPU being out of it.
//! The sequence runs with interrupts off and the thread verified to still be
//! on the CPU it prepared for; the pages (VMXON region, the MSR bitmap, the
//! vCPU's VMCS) are allocated with interrupts on, before it.
//!
//! # What the entry saves
//!
//! The VM exit restores the segments, the control registers, `GS` and `FS`
//! bases, `TR`, the descriptor-table bases, the SYSENTER MSRs, PAT and EFER
//! from the host-state fields ([`super::vmx::HostState`], read from this CPU
//! each entry), the five SYSCALL / `SWAPGS` MSRs from the exit MSR list; it
//! leaves the `GDTR` / `IDTR` limits at 0xFFFF ([`Cpu::after_exit`] reloads
//! them), and `CR2` is the guest's (the entry saves and restores it). Debug
//! registers 0-3 and 6 are not switched, as on SVM ([`super::hw`]).

use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use super::cpuid::Leaf;
use super::probe::{FC_LOCK, FC_VMXON_OUTSIDE_SMX, MSR_IA32_FEATURE_CONTROL};
use super::vcpu::{self, Claim, Machine, Ran, VcpuMem, VmHost, PAGE};
use super::vmx::{self, Caps, Controls, Extra, HostState, Site, VmcsIo, VmxCpu, VmxRegs};
use crate::cpu::{self, rdmsr, wrmsr, IA32_EFER, IA32_FS_BASE, IA32_GS_BASE, RFLAGS_IF};

const MSR_SYSENTER_CS: u32 = 0x174;
const MSR_SYSENTER_ESP: u32 = 0x175;
const MSR_SYSENTER_EIP: u32 = 0x176;
const MSR_PAT: u32 = 0x277;
const CR4_VMXE: u64 = 1 << 13;

// ── the run stub ────────────────────────────────────────────────────────

// `azos_vmx_run(regs: rdi, launched: esi) -> eax`: 0 when the guest ran and
// exited, 1 when `VMLAUNCH` / `VMRESUME` (or the `VMWRITE` of the host stack
// pointer) itself failed.
//
// Nothing survives the guest, so the host's callee-saved registers and the
// `regs` pointer go on the stack, and `HOST_RSP` is set to that stack (every
// exit lands on `azos_vmx_exit` with it). Offsets into `VmxRegs` are the field
// order, pinned by a host test: rax 0, rbx 8, rcx 16, rdx 24, rsi 32, rdi 40,
// rbp 48, r8 56 .. r15 112. `test` runs before the loads and `mov` does not
// touch the flags, so ZF still says "launched" at the branch.
global_asm!(
    ".section .text.azos_vmx_run,\"ax\",@progbits",
    ".global azos_vmx_run",
    ".type azos_vmx_run,@function",
    "azos_vmx_run:",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "push rdi",
    "mov eax, 0x6C14",
    "vmwrite rax, rsp",
    "jbe .Lvmx_fail",
    "test esi, esi",
    "mov rax, [rdi + 0]",
    "mov rbx, [rdi + 8]",
    "mov rcx, [rdi + 16]",
    "mov rdx, [rdi + 24]",
    "mov rsi, [rdi + 32]",
    "mov rbp, [rdi + 48]",
    "mov r8,  [rdi + 56]",
    "mov r9,  [rdi + 64]",
    "mov r10, [rdi + 72]",
    "mov r11, [rdi + 80]",
    "mov r12, [rdi + 88]",
    "mov r13, [rdi + 96]",
    "mov r14, [rdi + 104]",
    "mov r15, [rdi + 112]",
    "mov rdi, [rdi + 40]",
    "jnz .Lvmx_resume",
    "vmlaunch",
    "jmp .Lvmx_fail",
    ".Lvmx_resume:",
    "vmresume",
    ".Lvmx_fail:",
    "add rsp, 8",
    "mov eax, 1",
    "jmp .Lvmx_done",
    ".global azos_vmx_exit",
    ".type azos_vmx_exit,@function",
    "azos_vmx_exit:",
    "push rdi",
    "mov rdi, [rsp + 8]",
    "mov [rdi + 0], rax",
    "mov [rdi + 8], rbx",
    "mov [rdi + 16], rcx",
    "mov [rdi + 24], rdx",
    "mov [rdi + 32], rsi",
    "mov [rdi + 48], rbp",
    "mov [rdi + 56], r8",
    "mov [rdi + 64], r9",
    "mov [rdi + 72], r10",
    "mov [rdi + 80], r11",
    "mov [rdi + 88], r12",
    "mov [rdi + 96], r13",
    "mov [rdi + 104], r14",
    "mov [rdi + 112], r15",
    "pop rax",
    "mov [rdi + 40], rax",
    "add rsp, 8",
    "xor eax, eax",
    ".Lvmx_done:",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "ret",
    ".size azos_vmx_run, . - azos_vmx_run",
);

unsafe extern "C" {
    fn azos_vmx_run(regs: *mut VmxRegs, launched: u32) -> u32;
    fn azos_vmx_exit();
}

// ── the instructions ────────────────────────────────────────────────────

/// `VMXON` with the region at `pa`. `false`: VMfail (CF or ZF set).
fn vmxon(pa: u64) -> bool {
    let ok: u8;
    // SAFETY: CPL 0 with CR4.VMXE set, outside VMX operation; the operand is a
    // local holding the region's physical address.
    unsafe { asm!("vmxon qword ptr [{p}]", "setna {ok}", p = in(reg) &pa, ok = out(reg_byte) ok, options(nostack)) };
    ok == 0
}

fn vmclear(pa: u64) -> bool {
    let ok: u8;
    // SAFETY: VMX root operation; `pa` is a page of VMCS memory this vCPU owns.
    unsafe { asm!("vmclear qword ptr [{p}]", "setna {ok}", p = in(reg) &pa, ok = out(reg_byte) ok, options(nostack)) };
    ok == 0
}

fn vmptrld(pa: u64) -> bool {
    let ok: u8;
    // SAFETY: as `vmclear`; the page holds the revision identifier.
    unsafe { asm!("vmptrld qword ptr [{p}]", "setna {ok}", p = in(reg) &pa, ok = out(reg_byte) ok, options(nostack)) };
    ok == 0
}

fn vmread(field: u32) -> Option<u64> {
    let (v, ok): (u64, u8);
    // SAFETY: VMX root operation with a current VMCS.
    unsafe { asm!("vmread {v}, {f}", "setna {ok}", v = out(reg) v, f = in(reg) field as u64, ok = out(reg_byte) ok, options(nostack)) };
    (ok == 0).then_some(v)
}

fn vmwrite(field: u32, value: u64) -> bool {
    let ok: u8;
    // SAFETY: as `vmread`.
    unsafe { asm!("vmwrite {f}, {v}", "setna {ok}", f = in(reg) field as u64, v = in(reg) value, ok = out(reg_byte) ok, options(nostack)) };
    ok == 0
}

fn read_cr0() -> u64 {
    let v: u64;
    // SAFETY: reading a control register at CPL 0.
    unsafe { asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

fn read_cr4() -> u64 {
    let v: u64;
    // SAFETY: as `read_cr0`.
    unsafe { asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

fn write_cr4(v: u64) {
    // SAFETY: the caller keeps the bits the kernel runs with and adds VMXE.
    unsafe { asm!("mov cr4, {}", in(reg) v, options(nomem, nostack, preserves_flags)) };
}

fn xsetbv(xcr0: u64) {
    // SAFETY: CPL 0 with CR4.OSXSAVE set (`fp::init_cpu`); `xcr0` is the
    // host's own mask or a guest value `cpuid::xcr0_valid` accepted.
    unsafe {
        asm!("xsetbv", in("ecx") 0u32, in("eax") xcr0 as u32, in("edx") (xcr0 >> 32) as u32,
            options(nomem, nostack, preserves_flags));
    }
}

// ── the controls, resolved once ─────────────────────────────────────────

struct CtlCell(UnsafeCell<MaybeUninit<Controls>>);

// SAFETY: written once, under `CTL_STATE`'s claim, and read only after it
// says ready.
unsafe impl Sync for CtlCell {}

static CTL: CtlCell = CtlCell(UnsafeCell::new(MaybeUninit::uninit()));
/// 0 not resolved, 1 being resolved, 2 ready, 3 this CPU cannot run the backend.
static CTL_STATE: AtomicU8 = AtomicU8::new(0);

/// The controls this CPU runs a guest with, or `None` if it lacks one the
/// backend needs ([`Controls::resolve`]). Every CPU of a machine has the
/// same capability MSRs, so the boot CPU's reads stand for all.
pub fn controls() -> Option<Controls> {
    loop {
        match CTL_STATE.load(Ordering::Acquire) {
            2 => {
                // SAFETY: state 2 is published after the write below.
                return Some(unsafe { (*CTL.0.get()).assume_init() });
            }
            3 => return None,
            0 if CTL_STATE.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_ok() => {
                match Controls::resolve(&Caps::read(rdmsr)) {
                    Ok(k) => {
                        // SAFETY: state 1 is ours.
                        unsafe { (*CTL.0.get()).write(k) };
                        CTL_STATE.store(2, Ordering::Release);
                    }
                    Err(_) => CTL_STATE.store(3, Ordering::Release),
                }
            }
            _ => core::hint::spin_loop(),
        }
    }
}

// ── VMX operation, per CPU ──────────────────────────────────────────────

/// Per CPU: the VMXON region's physical address, 0 until the CPU first runs a guest.
static REGION: [AtomicU64; azos_limits::NR_CPUS] = [const { AtomicU64::new(0) }; azos_limits::NR_CPUS];
/// Per CPU: `VMXON` has been executed.
static ON: [AtomicBool; azos_limits::NR_CPUS] = [const { AtomicBool::new(false) }; azos_limits::NR_CPUS];

/// Enter VMX operation on this CPU: the lock bits firmware may have left
/// open, `CR4.VMXE` (the other bits the capability MSRs fix are the
/// kernel's already, or the CPU is refused), `VMXON`. Interrupts off. `false`
/// if firmware locked VMX off or a fixed bit conflicts with the kernel's.
fn enable_this_cpu(k: &Controls, region_pa: u64) -> bool {
    let fc = rdmsr(MSR_IA32_FEATURE_CONTROL);
    if fc & FC_LOCK == 0 {
        wrmsr(MSR_IA32_FEATURE_CONTROL, fc | FC_LOCK | FC_VMXON_OUTSIDE_SMX);
    } else if fc & FC_VMXON_OUTSIDE_SMX == 0 {
        return false;
    }
    let (cr0, cr4) = (read_cr0(), read_cr4() | CR4_VMXE | k.cr4_forced);
    let caps = Caps::read(rdmsr);
    if cr0 & caps.cr0_fixed0 != caps.cr0_fixed0 || cr0 & !caps.cr0_fixed1 != 0 || cr4 & !caps.cr4_fixed1 != 0 {
        return false;
    }
    write_cr4(cr4);
    vmxon(region_pa)
}

/// The CPU the shared entry runs on, for VMX: the same host plumbing as
/// `hw::Hw` (delegated), the VMX run in place of `VMRUN`.
pub struct VmxHw<'a>(pub super::hw::Hw<'a>);

impl VmxHw<'_> {
    fn host(&self) -> &dyn VmHost {
        self.0 .0
    }

    /// Interrupts off on a CPU in VMX operation. The region page is allocated
    /// with interrupts on (the check repeated: the thread may have moved).
    fn irqs_off_in_vmx(&self, k: &Controls) -> Option<u64> {
        for _ in 0..4 {
            let flags = cpu::rflags();
            cpu::cli();
            let me = cpu::percpu_id() % REGION.len();
            if ON[me].load(Ordering::Acquire) {
                return Some(flags);
            }
            let pa = REGION[me].load(Ordering::Acquire);
            if pa != 0 {
                if enable_this_cpu(k, pa) {
                    ON[me].store(true, Ordering::Release);
                    return Some(flags);
                }
                if flags & RFLAGS_IF != 0 {
                    cpu::sti();
                }
                return None;
            }
            if flags & RFLAGS_IF != 0 {
                cpu::sti();
            }
            let pa = self.host().alloc_pages(1)?;
            // SAFETY: a zeroed page the host gave, mapped by the machine; the
            // first word is the revision identifier (bit 31 clear).
            unsafe { (self.0.map(pa) as *mut u32).write_volatile(k.revision) };
            if REGION[me].compare_exchange(0, pa, Ordering::AcqRel, Ordering::Acquire).is_err() {
                self.host().free_pages(pa, 1);
            }
        }
        None
    }
}

/// The MSR bitmap every vCPU shares: built on first use.
static MSR_BITMAP: AtomicU64 = AtomicU64::new(0);

fn msr_bitmap(host: &dyn VmHost, m: &dyn Machine) -> Option<u64> {
    let pa = MSR_BITMAP.load(Ordering::Acquire);
    if pa != 0 {
        return Some(pa);
    }
    let pa = host.alloc_pages(1)?;
    // SAFETY: a page the host just gave, mapped by the machine, one bitmap long.
    vmx::build_msr_bitmap(unsafe { &mut *(m.map(pa) as *mut [u8; vmx::MSR_BITMAP_BYTES]) });
    match MSR_BITMAP.compare_exchange(0, pa, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Some(pa),
        Err(won) => {
            host.free_pages(pa, 1);
            Some(won)
        }
    }
}

impl Machine for VmxHw<'_> {
    fn cpu(&self) -> usize {
        self.0.cpu()
    }

    fn host_tsc(&self) -> u64 {
        self.0.host_tsc()
    }

    fn ticks_to_tsc(&self, ticks: u64) -> u64 {
        self.0.ticks_to_tsc(ticks)
    }

    fn host_cpuid(&self, leaf: u32, sub: u32) -> Leaf {
        self.0.host_cpuid(leaf, sub)
    }

    fn svm_caps(&self) -> super::probe::SvmCaps {
        vmx::svm_caps()
    }

    fn fp_bytes(&self) -> usize {
        self.0.fp_bytes()
    }

    fn extra_pages(&self) -> usize {
        vmx::EXTRA_PAGES
    }

    fn read_phys(&self, pa: u64, buf: &mut [u8]) -> bool {
        self.0.read_phys(pa, buf)
    }

    fn map(&self, pa: u64) -> *mut u8 {
        self.0.map(pa)
    }

    /// `cli`; VMX operation; guest FP state in; the guest's `XCR0`; the
    /// entry ([`vmx::run`]); the host's `XCR0`; guest FP state out; the
    /// interrupt flag back (a host interrupt that ended the entry is taken
    /// here).
    fn vmrun(&mut self, v: &mut VcpuMem, fp: *mut u8, guest_xcr0: u64, cpu: usize, claim: &Claim) -> Ran {
        let Some(k) = controls() else { return Ran::NoSvm };
        let Some(bitmap) = msr_bitmap(self.host(), &*self) else { return Ran::NoSvm };
        let Some(flags) = self.irqs_off_in_vmx(&k) else { return Ran::NoSvm };
        // percpu-hint: compared after `cli` (irqs_off_in_vmx): a move is Ran::Moved
        if cpu::percpu_id() != cpu {
            if flags & RFLAGS_IF != 0 {
                cpu::sti();
            }
            return Ran::Moved;
        }
        let host_xcr0 = crate::fp::xcr0();
        let extra = vcpu::extra_offset(self.fp_bytes()) - vcpu::fp_offset();
        let site_pa = v.run.pa + (vcpu::fp_offset() + extra) as u64;
        let site = Site { vmcs_pa: site_pa, extra_pa: site_pa + PAGE as u64, msr_bitmap_pa: bitmap };
        // SAFETY: the vCPU's pages end with `EXTRA_PAGES` pages the entry
        // owns (`Machine::extra_pages`), page-aligned; the first is the VMCS,
        // whose first word is the revision identifier, the second is `Extra`.
        let (vmcs, x) = unsafe {
            let vmcs = fp.add(extra);
            (vmcs as *mut u32, &mut *(vmcs.add(PAGE) as *mut Extra))
        };
        // SAFETY: interrupts are off on a CPU in VMX operation; `fp` is the
        // vCPU's own area of `fp::area_bytes()` bytes, 64-aligned, holding
        // `init_area`'s image or a state saved here; the pages are owned and
        // distinct; the thread does not migrate with interrupts off.
        unsafe {
            vmcs.write_volatile(k.revision);
            crate::fp::restore_eager(fp);
            if guest_xcr0 != host_xcr0 {
                xsetbv(guest_xcr0);
            }
            vmx::run(&mut Cpu::new(), &k, &site, v, x, claim, cpu, &|pa, buf| self.0.read_phys(pa, buf));
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

// ── the CPU, for `vmx::run` ─────────────────────────────────────────────

/// This CPU in VMX root operation. Built per entry; holds the descriptor
/// table registers the exit clobbers.
struct Cpu {
    gdt: [u8; 10],
    idt: [u8; 10],
    failed: bool,
}

impl Cpu {
    fn new() -> Cpu {
        Cpu { gdt: [0; 10], idt: [0; 10], failed: false }
    }
}

impl VmcsIo for Cpu {
    fn read(&mut self, field: u32) -> u64 {
        vmread(field).unwrap_or_else(|| {
            self.failed = true;
            0
        })
    }

    fn write(&mut self, field: u32, value: u64) {
        if !vmwrite(field, value) {
            self.failed = true;
        }
    }
}

/// The selectors the exit restores: CS, SS, DS, ES, FS, GS, TR.
fn selectors() -> [u16; 7] {
    let mut v = [0u16; 7];
    // SAFETY: each instruction stores a segment register's selector.
    unsafe {
        asm!("mov {0:x}, cs", out(reg) v[0], options(nomem, nostack, preserves_flags));
        asm!("mov {0:x}, ss", out(reg) v[1], options(nomem, nostack, preserves_flags));
        asm!("mov {0:x}, ds", out(reg) v[2], options(nomem, nostack, preserves_flags));
        asm!("mov {0:x}, es", out(reg) v[3], options(nomem, nostack, preserves_flags));
        asm!("mov {0:x}, fs", out(reg) v[4], options(nomem, nostack, preserves_flags));
        asm!("mov {0:x}, gs", out(reg) v[5], options(nomem, nostack, preserves_flags));
        asm!("str {0:x}", out(reg) v[6], options(nomem, nostack, preserves_flags));
    }
    v
}

impl VmxCpu for Cpu {
    fn host_state(&mut self) -> HostState {
        // SAFETY: store the descriptor-table registers into 10-byte buffers.
        unsafe {
            asm!("sgdt [{}]", in(reg) self.gdt.as_mut_ptr(), options(nostack, preserves_flags));
            asm!("sidt [{}]", in(reg) self.idt.as_mut_ptr(), options(nostack, preserves_flags));
        }
        let base = |b: &[u8; 10]| u64::from_le_bytes([b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9]]);
        let (gdtr, idtr) = (base(&self.gdt), base(&self.idt));
        let [cs, ss, ds, es, fs, gs, tr] = selectors();
        // SAFETY: the task register's descriptor is two words of the GDT the
        // CPU is running with, which maps itself.
        let tr_base = unsafe {
            let d = (gdtr + (tr & !7) as u64) as *const u64;
            vmx::tss_base(d.read_volatile(), d.add(1).read_volatile())
        };
        // The exit loads these with RPL 0 and TI 0 only.
        let data = |s: u16| s & !7;
        let cr3: u64;
        // SAFETY: reading CR3 at CPL 0. The PCID in its low bits (CR4.PCIDE) stays: the exit
        // loads the address space the host was running in.
        unsafe { asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)) };
        HostState {
            cr0: read_cr0(),
            cr3,
            cr4: read_cr4(),
            cs,
            ss,
            ds: data(ds),
            es: data(es),
            fs: data(fs),
            gs: data(gs),
            tr,
            fs_base: rdmsr(IA32_FS_BASE),
            gs_base: rdmsr(IA32_GS_BASE),
            tr_base,
            gdtr_base: gdtr,
            idtr_base: idtr,
            sysenter_cs: rdmsr(MSR_SYSENTER_CS) as u32,
            sysenter_esp: rdmsr(MSR_SYSENTER_ESP),
            sysenter_eip: rdmsr(MSR_SYSENTER_EIP),
            pat: rdmsr(MSR_PAT),
            efer: rdmsr(IA32_EFER),
            rip: azos_vmx_exit as *const () as usize as u64,
        }
    }

    fn rdmsr(&mut self, msr: u32) -> u64 {
        rdmsr(msr)
    }

    fn cr2(&mut self) -> u64 {
        cpu::read_cr2()
    }

    fn set_cr2(&mut self, v: u64) {
        // SAFETY: CR2 holds the last page-fault address; the guest's value is
        // loaded for its run and the host's put back before interrupts are on.
        unsafe { asm!("mov cr2, {}", in(reg) v, options(nomem, nostack, preserves_flags)) };
    }

    fn vmclear(&mut self, pa: u64) -> bool {
        vmclear(pa)
    }

    fn vmptrld(&mut self, pa: u64) -> bool {
        vmptrld(pa)
    }

    fn invept(&mut self, single: bool, eptp: u64) {
        let desc = [eptp, 0u64];
        let ty: u64 = if single { 1 } else { 2 };
        // SAFETY: VMX root operation; the descriptor is a 128-bit local. A
        // VMfail (unsupported type) leaves the tables as stale as they were,
        // which `Controls::resolve` has ruled out.
        unsafe { asm!("invept {t}, [{d}]", t = in(reg) ty, d = in(reg) desc.as_ptr(), options(nostack)) };
    }

    fn invvpid(&mut self, single: bool, vpid: u16) {
        let desc = [vpid as u64, 0u64];
        let ty: u64 = if single { 1 } else { 2 };
        // SAFETY: as `invept`.
        unsafe { asm!("invvpid {t}, [{d}]", t = in(reg) ty, d = in(reg) desc.as_ptr(), options(nostack)) };
    }

    fn enter(&mut self, regs: &mut VmxRegs, launched: bool) -> bool {
        // SAFETY: a current VMCS filled by `vmx::load`; the stub preserves the
        // host's callee-saved registers and restores the stack.
        unsafe { azos_vmx_run(regs, launched as u32) == 0 }
    }

    fn after_exit(&mut self) {
        // SAFETY: the exit left both limits at 0xFFFF; these are the values
        // `host_state` stored.
        unsafe {
            asm!("lgdt [{}]", in(reg) self.gdt.as_ptr(), options(readonly, nostack, preserves_flags));
            asm!("lidt [{}]", in(reg) self.idt.as_ptr(), options(readonly, nostack, preserves_flags));
        }
    }

    fn take_nmi(&mut self) {
        // SAFETY: a physical NMI ended the entry and was not delivered; the
        // host's handler (vector 2) runs as it would have, and its `IRET`
        // ends the NMI blocking the exit left on.
        unsafe { asm!("int 2") };
    }

    fn io_failed(&mut self) -> bool {
        core::mem::take(&mut self.failed)
    }
}

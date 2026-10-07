// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wave 8 — cross-hart TLB shootdown, observed (`tlb-smoke`, -smp >= 3).
//!
//! A "toucher" task pinned to one hart is given a private page table P whose
//! only non-kernel mapping is one page at `VA`, and is switched onto it by the
//! ordinary scheduler path (it sets its own `task_satp` and sleeps, so the
//! re-dispatch goes through `context_switch.S`: on riscv64 that is also where
//! the hart publishes P for the shootdown's mask). With interrupts off — a
//! tick would switch address spaces and flush, which would make the test pass
//! for the wrong reason — it reads `VA` (the translation is now in its TLB)
//! and spins. The runner, on another hart, removes the mapping with the real
//! `vmm::unmap`, then overwrites the frame the PTE used to name, which is what
//! reuse of a freed frame looks like. The toucher reads `VA` again through a
//! fault-catching load:
//!
//!   * shootdown working: the load FAULTS → `[TLB-SMOKE] PASS`
//!   * shootdown missing (`tlb-local-only`, the canary): the stale entry
//!     still translates and the load returns the NEW bytes of a frame the
//!     address space no longer owns → `[TLB-SMOKE] STALE READ`, a line only
//!     that path prints.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use azos_arch::{PagePerms, Cpu};
use azos_drv_sys::kprintln;
use azos_mm::{addr, pmm, vmm};

pub const PROBE_PRIO: u32 = 4;

/// Far from every mapping on both ISAs (riscv64 vpn2 = 128; inside
/// aarch64's 39-bit TTBR0 range); P is private. Checked at run time anyway.
const VA: usize = 0x20_0000_0000;
/// Second page: removed through `unmap_user_range_and_free`, the batched
/// path `munmap` takes, where `VA` goes through `vmm::unmap` (shm, io_ring,
/// mmap unwind, MMIO rollback).
const VA2: usize = VA + azos_arch::PAGE_SIZE;
const OLD: u64 = 0xA5A5_A5A5_A5A5_A5A5;
const NEW: u64 = 0x5A5A_5A5A_5A5A_5A5A;

static STAGE: AtomicU32 = AtomicU32::new(0);
static P_ROOT: AtomicUsize = AtomicUsize::new(0);
static FIRST: AtomicU64 = AtomicU64::new(0);
static FIRST_CAUSE: AtomicU64 = AtomicU64::new(u64::MAX);
static SECOND: AtomicU64 = AtomicU64::new(0);
static SECOND_CAUSE: AtomicU64 = AtomicU64::new(u64::MAX);
static SECOND2: AtomicU64 = AtomicU64::new(0);
static SECOND2_CAUSE: AtomicU64 = AtomicU64::new(u64::MAX);
static TOUCH_HART: AtomicUsize = AtomicUsize::new(usize::MAX);
/// Wave 9: the translation root `ktask` found itself on (`u64::MAX`: it
/// never ran), and the one the toucher was on when it created it.
static KTASK_ROOT: AtomicU64 = AtomicU64::new(u64::MAX);
static KTASK_CREATOR_ROOT: AtomicU64 = AtomicU64::new(u64::MAX);

/// This hart's live translation root, as the context switch writes it.
fn live_root() -> u64 {
    #[cfg(target_arch = "riscv64")]
    { azos_arch::csr::read_satp() as u64 }
    #[cfg(target_arch = "aarch64")]
    { azos_arch::sysregs::read_ttbr0_el1() & ((1 << 48) - 1) }
}

/// Wave 9: a kernel task created by a task that runs on a user root (the
/// toucher, on P) must run on the KERNEL's root. It used to inherit the
/// creator's live `satp` (riscv64), so it ran on a table its creator's
/// exit frees. Pinned to the toucher's hart, so on a kernel with the bug
/// no OTHER hart publishes P and the shootdown verdict above is unchanged.
fn ktask(_: usize) {
    KTASK_ROOT.store(live_root(), Ordering::SeqCst);
    azos_sched::task_exit();
}

#[repr(C)]
struct Load { value: u64, cause: u64 }

unsafe extern "C" {
    /// One 8-byte load from `va` with the trap vector pointed at a handler
    /// of its own; `cause` 0 = no fault, else `scause` / `ESR_EL1`.
    /// Interrupts are masked for the window and restored. Two-word
    /// aggregate: returned in a0/a1 (LP64) or x0/x1 (AAPCS64).
    fn azos_tlb_probe_load(va: usize) -> Load;
}

// riscv64: the shape of `azos_stimecmp_probe` (drivers/src/clint.rs).
#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".pushsection .text.azos_tlb_probe_load, \"ax\"",
    ".globl azos_tlb_probe_load",
    ".p2align 2",
    "azos_tlb_probe_load:",
    "    csrrci t3, sstatus, 2",
    "    csrr   t1, stvec",
    "    la     t0, 1f",
    "    csrw   stvec, t0",
    "    li     a1, 0",
    "    ld     a0, 0(a0)",
    "2:",
    "    csrw   stvec, t1",
    "    andi   t3, t3, 2",
    "    csrs   sstatus, t3",
    "    ret",
    ".p2align 2",
    "1:",
    "    csrr   a1, scause",
    "    li     a0, 0",
    "    la     t0, 2b",
    "    csrw   sepc, t0",
    "    sret",
    ".popsection",
);

// aarch64: a private vector table (2 KiB aligned) whose current-EL
// synchronous slots (SP0 at 0x000, SPx at 0x200) resume after the load.
// Everything else is masked for the window.
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".pushsection .text.azos_tlb_probe_load, \"ax\"",
    ".globl azos_tlb_probe_load",
    ".p2align 2",
    "azos_tlb_probe_load:",
    "    mrs  x9, daif",
    "    msr  daifset, #0xf",
    "    mrs  x10, vbar_el1",
    "    adrp x11, azos_tlb_probe_vectors",
    "    add  x11, x11, :lo12:azos_tlb_probe_vectors",
    "    msr  vbar_el1, x11",
    "    isb",
    "    mov  x1, #0",
    "    ldr  x0, [x0]",
    "azos_tlb_probe_resume:",
    "    msr  vbar_el1, x10",
    "    isb",
    "    msr  daif, x9",
    "    ret",
    ".p2align 11",
    "azos_tlb_probe_vectors:",
    "    mrs  x1, esr_el1",
    "    mov  x0, #0",
    "    adr  x12, azos_tlb_probe_resume",
    "    msr  elr_el1, x12",
    "    eret",
    ".p2align 9",
    "    mrs  x1, esr_el1",
    "    mov  x0, #0",
    "    adr  x12, azos_tlb_probe_resume",
    "    msr  elr_el1, x12",
    "    eret",
    ".p2align 11",
    ".popsection",
);

/// The value this ISA's context switch installs for "address space rooted
/// at `root`" (riscv64 `satp`, aarch64 raw `TTBR0_EL1`).
fn as_value(root: usize) -> usize {
    #[cfg(target_arch = "riscv64")]
    { azos_arch::mmu::make_satp(root, 0) }
    #[cfg(target_arch = "aarch64")]
    { root }
}

/// Does the hart's translation register name `root` right now?
fn running_on(root: usize) -> bool {
    #[cfg(target_arch = "riscv64")]
    { azos_arch::csr::read_satp() == azos_arch::mmu::make_satp(root, 0) }
    #[cfg(target_arch = "aarch64")]
    { (azos_arch::sysregs::read_ttbr0_el1() as usize) & ((1 << 48) - 1) == root }
}

/// The remote harts the shootdown must reach, read the way it reads them.
/// aarch64 needs none: `TLBI ...IS` is a hardware broadcast.
fn remote_mask(root: usize) -> usize {
    #[cfg(target_arch = "riscv64")]
    {
        azos_arch::tlb::remote_mask(
            |h| azos_arch::tlb::AZOS_HART_SATP[h].load(Ordering::SeqCst),
            azos_arch::tlb::TLB_MAX_HARTS, azos_arch::ARCH.hart_id(), root)
    }
    #[cfg(target_arch = "aarch64")]
    { let _ = root; 0 }
}

/// Is `cause` the translation fault an unmapped page must raise?
fn is_translation_fault(cause: u64) -> bool {
    #[cfg(target_arch = "riscv64")]
    { cause == 13 } // load page fault
    #[cfg(target_arch = "aarch64")]
    { (cause >> 26) & 0x3f == 0x25 && cause & 0x3c == 0x04 } // DABT same EL, translation L0-3
}

fn irq_off() -> usize {
    let saved: usize;
    #[cfg(target_arch = "riscv64")]
    unsafe { core::arch::asm!("csrrci {0}, sstatus, 2", out(reg) saved) };
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("mrs {0}, daif", "msr daifset, #2", out(reg) saved) };
    saved
}

fn irq_restore(saved: usize) {
    #[cfg(target_arch = "riscv64")]
    if saved & 2 != 0 { unsafe { core::arch::asm!("csrsi sstatus, 2") } }
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("msr daif, {0}", in(reg) saved) };
}

fn fill(frame: usize, word: u64) {
    let p = addr::phys_to_virt(frame) as *mut u64;
    for i in 0..(azos_arch::PAGE_SIZE / 8) {
        unsafe { core::ptr::write_volatile(p.add(i), word) };
    }
    core::sync::atomic::fence(Ordering::SeqCst);
}

/// Counter ticks per second, in `ARCH.now_ticks()` units.
fn hz() -> u64 {
    #[cfg(target_arch = "riscv64")]
    { azos_drv_sys::timebase::TIMER_FREQ }
    #[cfg(target_arch = "aarch64")]
    { azos_arch::timer::freq_hz() }
}

fn sleep_ms(ms: u64) {
    let hz = hz();
    let ticks = core::cmp::max(1, hz / 1000 * ms);
    let dl = azos_arch::ARCH.now_ticks().wrapping_add(ticks);
    azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
}

/// Wait (sleeping) for `STAGE >= s`, up to `ms`. False on timeout.
fn wait_stage(s: u32, ms: u64) -> bool {
    let mut waited = 0;
    while STAGE.load(Ordering::SeqCst) < s {
        if waited >= ms { return false; }
        sleep_ms(5);
        waited += 5;
    }
    true
}

fn toucher(_: usize) {
    let root = P_ROOT.load(Ordering::SeqCst);
    // A kernel task's own value: the kernel satp on riscv64, 0 ("the
    // kernel's TTBR0") on aarch64 — see `try_task_create_affinity`.
    #[cfg(target_arch = "riscv64")]
    let own = azos_arch::csr::read_satp() as u64;
    #[cfg(target_arch = "aarch64")]
    let own = 0u64;
    // Become a task whose address space is P, then leave the hart so the
    // scheduler's own switch path installs it.
    azos_sched::set_current_user_info(as_value(root) as u64, 0, 0);
    sleep_ms(20);
    if running_on(root) {
        KTASK_CREATOR_ROOT.store(live_root(), Ordering::SeqCst);
        azos_sched::task_create_affinity("ktask-root", ktask, 0, PROBE_PRIO,
                                             azos_arch::ARCH.hart_id() as i8);
    }

    // From here to the second load: no interrupt, so no switch, so no flush.
    let saved = irq_off();
    TOUCH_HART.store(azos_arch::ARCH.hart_id(), Ordering::SeqCst);
    if running_on(root) {
        let r = unsafe { azos_tlb_probe_load(VA) };
        let r2 = unsafe { azos_tlb_probe_load(VA2) };
        FIRST.store(r.value | r2.value, Ordering::SeqCst);
        FIRST_CAUSE.store(r.cause | r2.cause, Ordering::SeqCst);
        STAGE.store(2, Ordering::SeqCst);
        // Bounded spin (~2 s of counter time) for the unmap + overwrite.
        let t0 = azos_arch::ARCH.now_ticks();
        let limit = hz() * 2;
        while STAGE.load(Ordering::SeqCst) < 3
            && azos_arch::ARCH.now_ticks().wrapping_sub(t0) < limit {
            core::hint::spin_loop();
        }
        if STAGE.load(Ordering::SeqCst) >= 3 {
            let r = unsafe { azos_tlb_probe_load(VA) };
            SECOND.store(r.value, Ordering::SeqCst);
            SECOND_CAUSE.store(r.cause, Ordering::SeqCst);
            let r = unsafe { azos_tlb_probe_load(VA2) };
            SECOND2.store(r.value, Ordering::SeqCst);
            SECOND2_CAUSE.store(r.cause, Ordering::SeqCst);
        }
    } else {
        FIRST_CAUSE.store(u64::MAX - 1, Ordering::SeqCst); // P was never installed
        STAGE.store(2, Ordering::SeqCst);
    }
    // Back to the kernel's own table through the same switch path before
    // anyone frees P: the sleep's switch to idle installs the kernel root
    // (and, on riscv64, publishes it), and nothing brings P back.
    azos_sched::set_current_user_info(own, 0, 0);
    irq_restore(saved);
    sleep_ms(5);
    STAGE.store(4, Ordering::SeqCst);
    azos_sched::task_exit();
}

pub fn runner(touch_hart: usize) {
    let me = azos_arch::ARCH.hart_id();
    // A boot-created kernel task: this is the kernel's root.
    let kernel_root = live_root();
    let (frame, frame2) = match (pmm::alloc_page(), pmm::alloc_page()) {
        (Ok(p), Ok(q)) => (p.as_usize(), q.as_usize()),
        _ => { kprintln!("[TLB-SMOKE] FAILED: no frame"); return; }
    };
    let pt = match vmm::create_pagetable() { Ok(p) => p, Err(_) => {
        kprintln!("[TLB-SMOKE] FAILED: no page table"); return; } };
    vmm::copy_kernel_entries_to_user(pt);
    if vmm::va_is_kernel_mapped(VA) || vmm::va_is_kernel_mapped(VA2)
        || vmm::map(pt, VA, frame, PagePerms::KERNEL_RW).is_err()
        || vmm::map(pt, VA2, frame2, PagePerms::KERNEL_RW).is_err() {
        kprintln!("[TLB-SMOKE] FAILED: could not map the probe page");
        return;
    }
    fill(frame, OLD);
    fill(frame2, OLD);
    P_ROOT.store(pt, Ordering::SeqCst);
    azos_sched::task_create_affinity("tlb-touch", toucher, 0, PROBE_PRIO, touch_hart as i8);

    if !wait_stage(2, 3000) {
        kprintln!("[TLB-SMOKE] FAILED: toucher never ran on hart {}", touch_hart);
        return;
    }
    let th = TOUCH_HART.load(Ordering::SeqCst);
    let first = FIRST.load(Ordering::SeqCst);
    let first_cause = FIRST_CAUSE.load(Ordering::SeqCst);
    if first_cause != 0 || first != OLD {
        kprintln!("[TLB-SMOKE] FAILED: setup read on hart {}: value={:#x} cause={:#x}",
            th, first, first_cause);
        let _ = wait_stage(4, 3000);
        return;
    }
    // Who the shootdown will have to reach (recomputed inside it; the
    // toucher is spinning on P, so this is what it sees).
    let mask = remote_mask(pt);

    // The revokes under test: the production unmap paths. The range call
    // frees nothing here (a kernel-permission leaf is not a task's own
    // frame) but clears, batches and shoots down exactly as `munmap` does.
    vmm::unmap(pt, VA);
    let _ = vmm::unmap_user_range_and_free(pt, VA2, VA2 + azos_arch::PAGE_SIZE, 0, 0);
    // Reuse of the frames the PTEs named.
    fill(frame, NEW);
    fill(frame2, NEW);
    STAGE.store(3, Ordering::SeqCst);

    if !wait_stage(4, 3000) {
        kprintln!("[TLB-SMOKE] FAILED: toucher did not finish");
        return;
    }
    // The kernel task the toucher created on P (it runs once the toucher
    // sleeps). Printed BEFORE the shootdown verdict: the aarch64 row stops
    // reading at the first `TLB-SMOKE]` line.
    let mut waited = 0;
    while KTASK_ROOT.load(Ordering::SeqCst) == u64::MAX && waited < 3000 {
        sleep_ms(5);
        waited += 5;
    }
    let kroot = KTASK_ROOT.load(Ordering::SeqCst);
    let croot = KTASK_CREATOR_ROOT.load(Ordering::SeqCst);
    if kroot == kernel_root && croot != kernel_root {
        kprintln!("[KTASK-ROOT] PASS: a kernel task created on a user root ({:#x}) runs on the kernel root ({:#x})",
            croot, kroot);
    } else {
        kprintln!("[KTASK-ROOT] FAILED: a kernel task created on root {:#x} runs on {:#x}, the kernel root is {:#x}",
            croot, kroot, kernel_root);
    }

    let v = SECOND.load(Ordering::SeqCst);
    let c = SECOND_CAUSE.load(Ordering::SeqCst);
    let v2 = SECOND2.load(Ordering::SeqCst);
    let c2 = SECOND2_CAUSE.load(Ordering::SeqCst);
    let after = remote_mask(pt);
    if c != 0 && is_translation_fault(c) && c2 != 0 && is_translation_fault(c2) {
        kprintln!("[TLB-SMOKE] PASS: hart {} faulted (cause={:#x}) on the page hart {} unmapped after the touch; remote mask={:#x} harts signalled={}; munmap path faulted too (cause={:#x}); mask after switch-away={:#x}",
            th, c, me, mask, mask.count_ones(), c2, after);
    } else if c == 0 || c2 == 0 {
        kprintln!("[TLB-SMOKE] STALE READ on hart {}: value={:#x} (unmap) value={:#x} (munmap path) after hart {} unmapped them (remote mask={:#x})",
            th, if c == 0 { v } else { 0 }, if c2 == 0 { v2 } else { 0 }, me, mask);
    } else {
        kprintln!("[TLB-SMOKE] FAILED: second read cause={:#x}/{:#x} value={:#x}/{:#x}", c, c2, v, v2);
    }
    // P is no longer anyone's translation root (the toucher switched away
    // and exited) — free it.
    if after == 0 {
        vmm::destroy_user_pagetable(pt);
        let _ = pmm::free_page(addr::PhysAddr::new(frame));
        let _ = pmm::free_page(addr::PhysAddr::new(frame2));
    }
}

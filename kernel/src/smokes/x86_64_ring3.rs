// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64: ring 3 without a user image (ktest `x86_ring3_syscall_fork_fp`).
//!
//! There are no x86_64 user images yet, so this test builds an address space
//! by hand: one page of code (the `x86_ring3_code` block below, copied to a
//! fresh frame), one page of stack and one result page, then a kernel task
//! takes that table as its own and enters ring 3 through the ordinary first
//! entry (`sret_to_user`). The code checks, in ring 3:
//!
//!   1. `SYS_GETPID` returns (the `syscall` entry and the `sysretq` return,
//!      or `iretq` with Kconfig `X86_SYSRET=n`), and XMM0 survives it;
//!   2. `SYS_FORK` gives a child whose XMM0 is the parent's (the fork
//!      snapshot carries the XSAVE image) and which exits 42;
//!   3. `SYS_WAITPID` writes that status to the parent's stack, a page the
//!      fork made copy-on-write (the kernel's write through SMAP's window
//!      breaks it).
//!
//! The parent writes what it saw to the result page, which sits in the
//! shm/MMIO window (`LOCKED_ARENA_VA`): fork neither shares nor copies that
//! window, so the parent's stores reach this frame, and the teardown at exit
//! does not free it. The test reads it back.

use core::sync::atomic::{AtomicUsize, Ordering};

use azos_arch::PagePerms;
use azos_mm::{addr, pmm, vmm};

/// The code page: in the user half, which holds no kernel RAM (the kernel
/// links and maps RAM at `KERNEL_VA_OFFSET`), outside every table the
/// kernel shares.
const CODE_VA: usize = 0x4000_0000;
const STACK_TOP: usize = azos_sched::process::USER_STACK_TOP;
const RESULT_VA: usize = azos_sched::process::LOCKED_ARENA_VA;
const MARK: u64 = 0x1122_3344_5566_7788;
const DONE: u64 = 0x600d;
const BAD: u64 = 0xbad;

core::arch::global_asm!(
    ".pushsection .rodata.x86_ring3_code, \"a\"",
    ".globl x86_ring3_code_start",
    ".globl x86_ring3_code_end",
    "x86_ring3_code_start:",
    "    subq $64, %rsp",
    "    movabsq ${result}, %r15",
    "    movabsq ${mark}, %rax",
    "    movq %rax, %xmm0",
    "    movl ${getpid}, %eax",
    "    syscall",
    "    movq %rax, 0(%r15)",
    "    movq %xmm0, %rbx",
    "    movabsq ${mark}, %rcx",
    "    cmpq %rcx, %rbx",
    "    jne 9f",
    "    movq $1, 8(%r15)",
    "    movl ${fork}, %eax",
    "    syscall",
    "    testq %rax, %rax",
    "    js 9f",
    "    jz 5f",
    "    movq %rax, %r12",
    "    movq %rax, 16(%r15)",
    "1:  movq %r12, %rdi",
    "    movq %rsp, %rsi",
    "    movl ${waitpid}, %eax",
    "    syscall",
    "    cmpq %r12, %rax",
    "    je 2f",
    "    movl ${yield_}, %eax",
    "    syscall",
    "    jmp 1b",
    "2:  movslq (%rsp), %rax",
    "    movq %rax, 24(%r15)",
    "    movq ${done}, 32(%r15)",
    "    xorl %edi, %edi",
    "    movl ${exit}, %eax",
    "    syscall",
    "5:  movq %xmm0, %rbx",
    "    movabsq ${mark}, %rcx",
    "    cmpq %rcx, %rbx",
    "    jne 6f",
    "    movl $42, %edi",
    "    movl ${exit}, %eax",
    "    syscall",
    "6:  movl $43, %edi",
    "    movl ${exit}, %eax",
    "    syscall",
    "9:  movq ${bad}, 32(%r15)",
    "    movl $1, %edi",
    "    movl ${exit}, %eax",
    "    syscall",
    "x86_ring3_code_end:",
    ".popsection",
    result = const RESULT_VA,
    mark = const MARK,
    done = const DONE,
    bad = const BAD,
    getpid = const azos_abi::syscall_nr::SYS_GETPID,
    fork = const azos_abi::syscall_nr::SYS_FORK,
    waitpid = const azos_abi::syscall_nr::SYS_WAITPID,
    yield_ = const azos_abi::syscall_nr::SYS_YIELD,
    exit = const azos_abi::syscall_nr::SYS_EXIT,
    options(att_syntax),
);

unsafe extern "C" {
    static x86_ring3_code_start: u8;
    static x86_ring3_code_end: u8;
}

static ROOT: AtomicUsize = AtomicUsize::new(0);
static RESULT_FRAME: AtomicUsize = AtomicUsize::new(0);

/// The task that becomes the ring-3 process.
fn user_task(_: usize) {
    use azos_arch::ArchPlatform;
    let root = ROOT.load(Ordering::Acquire);
    let word = azos_arch::ARCH.user_root_word(root, 0);
    azos_sched::set_current_user_info(word as u64, root as u64, 0);
    // SAFETY: `root` maps the code and stack pages USER and every kernel
    // entry; this kernel task never returns to its kernel stack.
    unsafe { azos_sched::sret_to_user(CODE_VA, STACK_TOP, word) }
}

fn result(i: usize) -> u64 {
    let p = addr::phys_to_virt(RESULT_FRAME.load(Ordering::Acquire)) as *const u64;
    // SAFETY: the result frame is this test's, mapped in the kernel's RAM map.
    unsafe { core::ptr::read_volatile(p.add(i)) }
}

fn setup() -> Result<(), &'static str> {
    let page = |_| pmm::alloc_page().map(|p| p.as_usize()).map_err(|_| "no frame");
    let (code, stack, res) = (page(0)?, page(1)?, page(2)?);
    let start = (&raw const x86_ring3_code_start) as usize;
    let len = (&raw const x86_ring3_code_end) as usize - start;
    // SAFETY: a fresh frame, mapped in the kernel's RAM map; the code block
    // is `len` bytes of .rodata.
    unsafe { core::ptr::copy_nonoverlapping(start as *const u8, addr::phys_to_virt(code) as *mut u8, len) };
    let root = vmm::create_pagetable().map_err(|_| "no page table")?;
    let ps = azos_arch::PAGE_SIZE;
    if vmm::map(root, CODE_VA, code, PagePerms::USER_RX).is_err()
        || vmm::map(root, STACK_TOP - ps, stack, PagePerms::USER_RW).is_err()
        || vmm::map(root, RESULT_VA, res, PagePerms::USER_RW).is_err()
    {
        return Err("could not map the user pages");
    }
    // Kernel entries last: the task's own tables exist first, and nothing of
    // theirs may sit where a kernel entry must go (the loader's order).
    if vmm::kernel_entry_collision(root).is_some() {
        return Err("the hand-built table collides with a kernel entry");
    }
    vmm::copy_kernel_entries_to_user(root);
    RESULT_FRAME.store(res, Ordering::Release);
    ROOT.store(root, Ordering::Release);
    Ok(())
}

azos_ktest::ktest_late! {
    fn x86_ring3_syscall_fork_fp() {
        setup()?;
        azos_sched::task_create("x86-ring3", user_task, 0, azos_sched::DEFAULT_PRIORITY);
        crate::ktest::wait("the ring-3 process never wrote its verdict", || result(4) != 0)?;
        if result(4) == BAD {
            return Err("ring 3: XMM0 changed across SYS_GETPID, or SYS_FORK failed");
        }
        if result(4) != DONE {
            return Err("ring 3: the verdict word is neither done nor bad");
        }
        if result(0) == 0 || result(0) > u32::MAX as u64 {
            return Err("SYS_GETPID returned no TID");
        }
        if result(1) != 1 {
            return Err("XMM0 did not survive the syscall");
        }
        if result(2) == 0 {
            return Err("SYS_FORK returned no child TID");
        }
        match result(3) {
            42 => Ok(()),
            43 => Err("the forked child's XMM0 is not the parent's"),
            _ => Err("SYS_WAITPID wrote another status than the child's 42"),
        }
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Linux runtime image (Kconfig `LINUX_RUNTIME`): `userspace/lib/linux_rt`
//! over the native ABI, linked at `azos_abi::foreign`'s runtime window and
//! embedded in the kernel image (`kernel/src/boot/seams.rs`).
//!
//! The kernel maps it into a Linux process's address space at spawn and
//! starts the process **here**, with the stack pointer at the Linux initial
//! stack it laid out (argc, argv, envp, the auxiliary vector), the second
//! argument register at the startup block of the spawn request (the
//! descriptors and working directory; 0 for a spawn with no request) and
//! every other register zero. `_start` registers [`lxrt_trap_entry`] with
//! `SYS_FOREIGN_ENTRY`, then resumes the program at its entry (`AT_ENTRY`)
//! with that same stack pointer and every register zero, which is exactly the
//! state a Linux process starts in. From then on each Linux system call the
//! program makes traps into [`lxrt_trap_entry`]: the kernel has pushed the
//! program's registers on its stack and passes their address (in `a0`/`x0`
//! and as the stack pointer). [`lxrt_trap`] answers the call, stores the
//! result in the frame, and resumes the program.
//!
//! Everything here runs on the program's own stack, between two of its
//! instructions, so it is built without floating point (riscv64imac, and
//! `aarch64-unknown-none-softfloat`): the program's FP/SIMD registers are
//! live the whole time.

#![no_std]
#![no_main]

// The runtime's entry assembly exists for the ISAs that have the personality.
#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
compile_error!(
    "lxrt: riscv64 or aarch64 only (the ISAs of the asm-generic table azos_linux_abi holds; \
     config/Kconfig.linux says what x86_64 needs)"
);

use azos_abi::foreign::{ForeignFrame, REG_SP};
use azos_libsys as sys;
use azos_linux_abi::at;
use azos_abi::ushell::{StartupBlock, STARTUP_BLOCK_SIZE};
use azos_linux_rt::{Native, Runtime, Startup, NAME_BYTES};

/// The native calls, over `azos_libsys`.
struct Sys;

impl Native for Sys {
    fn getpid(&self) -> i64 {
        sys::getpid() as i64
    }
    fn now_ns(&self) -> u64 {
        sys::vdso_now_ns()
    }
    fn console_write(&self, buf: &[u8]) -> i64 {
        sys::write(1, buf) as i64
    }
    fn file_open(&self, path: &[u8], flags: u64) -> i64 {
        sys::file_open_typed(path, flags) as i64
    }
    fn handle_read(&self, h: u32, buf: &mut [u8]) -> i64 {
        sys::file_read_typed(h, buf) as i64
    }
    fn handle_write(&self, h: u32, buf: &[u8]) -> i64 {
        sys::file_write_typed(h, buf) as i64
    }
    fn handle_close(&self, h: u32) -> i64 {
        sys::close_typed(h) as i64
    }
    fn pipe(&self, ends: &mut [u32; 2], nonblock: bool) -> i64 {
        sys::pipe_typed(ends, if nonblock { azos_abi::ushell::PIPE_NONBLOCK } else { 0 }) as i64
    }
    fn stat(&self, path: &[u8], out: &mut [u8; azos_abi::syscall_nr::STAT_BYTES]) -> i64 {
        sys::stat(path, out) as i64
    }
    fn readdir(&self, dir: &[u8], idx: u64, name: &mut [u8; NAME_BYTES], size: &mut u32, is_dir: &mut u32) -> i64 {
        sys::readdir(dir, idx, name, size, is_dir) as i64
    }
    fn brk(&self, addr: u64) -> i64 {
        sys::brk(addr) as i64
    }
    fn mmap(&self, addr: u64, len: u64, prot: u64, flags: u64) -> i64 {
        sys::mmap(addr, len, prot, flags, u64::MAX, 0) as i64
    }
    fn munmap(&self, addr: u64, len: u64) -> i64 {
        sys::munmap(addr, len) as i64
    }
    fn sleep_until_ns(&self, deadline_ns: u64) {
        let _ = sys::sleep_until_ns(deadline_ns);
    }
    fn yield_now(&self) {
        sys::yield_now();
    }
    fn fork(&self) -> i64 {
        sys::foreign_fork() as i64
    }
    fn waitpid(&self, tid: u32, code: &mut i32) -> i64 {
        sys::waitpid(tid, code as *mut i32) as i64
    }
    fn exit(&self, code: i32) -> ! {
        sys::exit(code)
    }
}

static RT: Runtime<Sys> = Runtime::new(Sys);

// The two entries. `_start`: the kernel starts the process here, `sp` at the
// Linux initial stack. `lxrt_trap_entry`: the kernel reflects a trap here with
// the frame's address in the first argument register and as `sp`; every
// register of the program is in the frame, so these may clobber any.
#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".section .text._start,\"ax\",@progbits",
    ".globl _start",
    "_start:",
    "    mv a0, sp",       // a1 stays: the startup block
    "    call lxrt_start",
    ".globl lxrt_trap_entry",
    "lxrt_trap_entry:",
    "    call lxrt_trap",
);
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".section .text._start,\"ax\",@progbits",
    ".globl _start",
    "_start:",
    "    mov x0, sp",      // x1 stays: the startup block
    "    bl lxrt_start",
    ".globl lxrt_trap_entry",
    "lxrt_trap_entry:",
    "    bl lxrt_trap",
);

unsafe extern "C" {
    /// The trap entry above.
    fn lxrt_trap_entry();
}

/// The Linux process starts: set the runtime up from the initial stack,
/// register the trap entry and resume the program at its entry point.
///
/// # Safety
/// `sp` is the stack pointer the kernel started the process with: the Linux
/// initial stack (`azos_linux_abi::layout_initial_stack`). `startup` is the
/// address of the spawn request's startup block, or 0.
#[unsafe(no_mangle)]
unsafe extern "C" fn lxrt_start(sp: *const u64, startup: u64) -> ! {
    // SAFETY: the kernel laid the stack out; argc, argv, envp and the
    // auxiliary vector are walked up to their terminators.
    let (entry, execfn) = unsafe {
        let argc = *sp as usize;
        let mut p = sp.add(1 + argc + 1);
        while *p != 0 {
            p = p.add(1);
        }
        p = p.add(1);
        let (mut entry, mut execfn) = (0u64, 0u64);
        while *p != at::NULL {
            match *p {
                at::ENTRY => entry = *p.add(1),
                at::EXECFN => execfn = *p.add(1),
                _ => {}
            }
            p = p.add(2);
        }
        (entry, execfn)
    };
    if entry == 0 {
        sys::exit(127);
    }
    // The image's name, for `/proc/self/exe`: what the kernel put in
    // `AT_EXECFN` (the first argument).
    let mut name = [0u8; 64];
    let mut n = 0;
    if execfn != 0 {
        // SAFETY: a NUL-terminated string on the initial stack.
        unsafe {
            while n < name.len() && *((execfn + n as u64) as *const u8) != 0 {
                name[n] = *((execfn + n as u64) as *const u8);
                n += 1;
            }
        }
    }
    // The spawn request's descriptors and working directory. A block that is
    // not the one this ABI writes is the kernel's bug, not a reason to run
    // the program on descriptors it did not ask for.
    let block = if startup == 0 {
        None
    } else {
        // SAFETY: the kernel wrote the block (and the strings it points at)
        // on this stack before the first instruction.
        let b = unsafe { StartupBlock::from_bytes(core::slice::from_raw_parts(startup as *const u8, STARTUP_BLOCK_SIZE)) };
        match b {
            Some(b) if b.validate() => Some(b),
            _ => sys::exit(122),
        }
    };
    // SAFETY: `cwd` names `cwd_bytes` bytes beside the block.
    let cwd = match &block {
        Some(b) if b.cwd != 0 => unsafe { core::slice::from_raw_parts(b.cwd as *const u8, b.cwd_bytes as usize) },
        _ => &[][..],
    };
    let given = block.as_ref().map(|b| Startup { fds: &b.fds, cwd });
    RT.init(&name[..n], given.as_ref());
    if sys::foreign_entry(lxrt_trap_entry as *const () as usize as u64) != 0 {
        sys::exit(126);
    }
    let mut frame = ForeignFrame::ZERO;
    frame.pc = entry;
    frame.gpr[REG_SP] = sp as u64;
    // SAFETY: `frame` is the state a Linux process starts in.
    unsafe { sys::foreign_resume(&frame) };
    sys::exit(125)
}

/// A Linux system call, reflected by the kernel: answer it and resume the
/// program.
///
/// # Safety
/// `frame` is the address of the frame the kernel pushed on the program's
/// stack (and the stack pointer on entry).
#[unsafe(no_mangle)]
unsafe extern "C" fn lxrt_trap(frame: *mut ForeignFrame) -> ! {
    // SAFETY: the kernel just wrote it; nothing else holds it.
    let f = unsafe { &mut *frame };
    RT.dispatch(f);
    // SAFETY: the frame, with the result in it.
    unsafe { sys::foreign_resume(frame) };
    sys::exit(124)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(123)
}

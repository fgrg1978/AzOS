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
//! instructions, so it is built without floating point (riscv64imac,
//! `aarch64-unknown-none-softfloat`, and `x86_64-unknown-none`, which is
//! soft-float and names no SSE register): the program's FP/SIMD registers are
//! live the whole time.
//!
//! On x86_64 the program's calls are Linux's x86-64 ones (another table, other
//! argument registers, other `struct stat`): [`lxrt_trap`] hands the frame to
//! [`Runtime::dispatch_x86_64`], which translates it to the call the runtime
//! answers (`azos_linux_abi::x86_64`). The kernel starts the process with the
//! startup block's address in `rsi` and reflects a trap with the frame's
//! address in `rdi` and as `rsp`, 16-byte aligned, below the program's red
//! zone.

#![no_std]
#![no_main]

// The runtime's entry assembly exists for the ISAs that have the personality.
#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("lxrt: riscv64, aarch64 or x86_64 only (the ISAs that host the Linux personality)");

use azos_abi::foreign::{ForeignFrame, REG_SP};
use azos_libsys as sys;
use azos_linux_abi::at;
use azos_abi::ushell::{StartupBlock, STARTUP_BLOCK_SIZE};
use azos_linux_rt::{Native, PipeReady, Runtime, Startup, NAME_BYTES};

/// The native calls, over `azos_libsys`.
struct Sys;

impl Native for Sys {
    fn getpid(&self) -> i64 {
        sys::getpid() as i64
    }
    fn now_ns(&self) -> u64 {
        sys::vdso_now_ns()
    }
    fn clock_ns(&self, id: azos_abi::time::ClockId) -> Result<u64, azos_abi::time::ClockError> {
        sys::clock_now(id)
    }
    fn console_write(&self, buf: &[u8]) -> i64 {
        sys::write(1, buf) as i64
    }
    fn file_open(&self, path: &[u8], flags: u64) -> i64 {
        // The runtime's POSIX paths resolve against the task's root `Cap<Dir>`.
        let root = sys::root_dir();
        if root < 0 {
            return root as i64;
        }
        let mut rel = path;
        while rel.first() == Some(&b'/') {
            rel = &rel[1..];
        }
        sys::open_at(root as u32, rel, flags) as i64
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
    // Pipes are byte rings in shared regions (`azos_libsys::pipe`); an end is
    // a token that `handle_read`, `handle_write` and `handle_close` above
    // already serve (`libsys` routes a token to its pipe).
    fn pipe(&self, ends: &mut [u32; 2], nonblock: bool) -> i64 {
        match sys::pipe::create() {
            Ok(t) => {
                if nonblock {
                    for e in t {
                        let _ = sys::pipe::set_nonblock(e, true);
                    }
                }
                *ends = t;
                0
            }
            Err(e) => e as i64,
        }
    }
    fn handle_is_pipe(&self, h: u32) -> bool {
        sys::pipe::is_token(h)
    }
    fn handle_set_nonblock(&self, h: u32, on: bool) {
        let _ = sys::pipe::set_nonblock(h, on);
    }
    fn pipe_ready(&self, h: u32) -> Option<PipeReady> {
        sys::pipe::ready(h).map(|r| PipeReady { write_end: r.end == sys::pipe::End::Write, ready: r.ready, hup: r.hup })
    }
    fn stat(&self, path: &[u8], out: &mut [u8; azos_abi::syscall_nr::STAT_BYTES]) -> Result<(), i64> {
        let (root, name) = sys::beneath_root(path).map_err(|e| e.to_syscall_ret())?;
        sys::stat_at(root, name, out).map_err(|e| e.to_syscall_ret())
    }
    fn readdir(&self, dir: &[u8], idx: u32, name: &mut [u8; NAME_BYTES]) -> Result<Option<(u32, bool)>, i64> {
        let (root, dir) = sys::beneath_root(dir).map_err(|e| e.to_syscall_ret())?;
        match sys::readdir_at(root, dir, idx, name) {
            Ok(e) => Ok(e.map(|e| (e.size, e.is_dir))),
            Err(e) => Err(e.to_syscall_ret()),
        }
    }
    fn page_size(&self) -> u64 {
        sys::PAGE_SIZE as u64
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
    // The child holds every pipe end the parent does, and shares the regions
    // (the kernel's fork rule for a `Cap<Shm>`, which counts the child's ends
    // in the same step). The process id the pipe locks record is the
    // parent's until the child says it forked.
    fn fork(&self) -> i64 {
        let r = sys::foreign_fork() as i64;
        if r == 0 {
            sys::pipe::forked();
        }
        r
    }
    fn waitpid(&self, tid: u32, code: &mut i32) -> i64 {
        sys::waitpid(tid, code as *mut i32) as i64
    }
    fn wait_block(&self, tid: u32, code: &mut i32) -> i64 {
        sys::wait_for(tid, code as *mut i32, azos_abi::invoke::WAIT_FOREVER) as i64
    }
    fn exit(&self, code: i32) -> ! {
        sys::exit(code)
    }
    // x86-64 `arch_prctl(ARCH_SET_FS)`, the only caller: `successor` below.
    fn handle_seek(&self, h: u32, offset: i64, whence: u32) -> i64 {
        sys::file_seek_typed(h, offset, u64::from(whence)) as i64
    }
    fn mprotect(&self, addr: u64, len: u64, prot: u64) -> i64 {
        sys::mprotect(addr, len, prot) as i64
    }
    fn futex_wait(&self, addr: u64, expected: u32, timeout_ns: u64) -> i64 {
        sys::futex_wait_addr(addr as usize, expected, timeout_ns) as i64
    }
    fn futex_wake(&self, addr: u64, n: u32) -> i64 {
        sys::futex_wake_addr(addr as usize, n) as i64
    }
    fn futex_lock_pi(&self, addr: u64, timeout_ns: u64, try_only: bool) -> i64 {
        if try_only {
            sys::futex_trylock_pi_addr(addr as usize) as i64
        } else {
            sys::futex_lock_pi_addr(addr as usize, timeout_ns) as i64
        }
    }
    fn futex_unlock_pi(&self, addr: u64) -> i64 {
        sys::futex_unlock_pi_addr(addr as usize) as i64
    }
    fn alert(&self, tid: u32, signo: u32) -> i64 {
        sys::task_kill(tid, azos_abi::ushell::KILL_REQUEST | azos_abi::ushell::KILL_FORCE, u64::from(signo), 0) as i64
    }
    fn sigreturn_code(&self) -> u64 {
        lxrt_sigreturn as *const () as usize as u64
    }
    fn thread_create(&self, start: &ForeignFrame, newsp: u64, clear_tid: u64, tls: u64, settid: [u64; 2]) -> i64 {
        let size = core::mem::size_of::<ThreadStart>() as u64;
        if newsp < size + 256 {
            return azos_abi::error::Errno::EINVAL.to_syscall_ret();
        }
        // The hand-over block goes just below the new stack pointer, where the
        // thread's trampoline runs: the program's own use of that stack begins
        // only after the trampoline has resumed it.
        let at = (newsp - size) & !15;
        // SAFETY: the new thread's stack, which nothing runs on yet.
        unsafe { core::ptr::write(at as *mut ThreadStart, ThreadStart { frame: *start, settid }) };
        sys::thread_create_with_tls(lxrt_thread_start, at as usize, at, clear_tid as *mut u32, tls) as i64
    }
    fn thread_exit(&self, code: i32) -> ! {
        sys::thread_exit(code)
    }
    fn set_clear_tid(&self, addr: u64) -> i64 {
        sys::set_clear_tid(addr) as i64
    }
    fn thread_pointer(&self) -> u64 {
        let tp: u64;
        // SAFETY: reads a register the program owns; the runtime never writes it.
        #[cfg(target_arch = "riscv64")]
        unsafe {
            core::arch::asm!("mv {}, tp", out(reg) tp, options(nomem, nostack));
        }
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("mrs {}, tpidr_el0", out(reg) tp, options(nomem, nostack));
        }
        // x86-64: ring 3 cannot read its FS base; the runtime keeps the one it installed.
        #[cfg(target_arch = "x86_64")]
        {
            tp = 0;
        }
        tp
    }
    // The pipe ends are shared (the region's capability goes in the list, the
    // kernel counts the end the image's fd position names: a read end only on
    // fd 0, a write end on 1..), the files are moved.
    fn spawn_image(&self, img: &azos_linux_rt::SpawnImage) -> i64 {
        use azos_abi::ushell::{Move, SpawnReq, MOVE_CONSOLE, SPAWN_F_DIE_WITH_PARENT, SPAWN_REQ_VERSION};
        let mut req = SpawnReq {
            version: SPAWN_REQ_VERSION,
            // A signal that ends this process (it is the pid the caller's parent
            // knows) ends the image with it.
            flags: SPAWN_F_DIE_WITH_PARENT,
            argv_ptr: if img.argv.is_empty() { 0 } else { img.argv.as_ptr() as u64 },
            argv_bytes: img.argv.len() as u32,
            argc: img.argc,
            env_ptr: if img.env.is_empty() { 0 } else { img.env.as_ptr() as u64 },
            env_bytes: img.env.len() as u32,
            envc: img.envc,
            cwd_ptr: img.cwd.as_ptr() as u64,
            ..SpawnReq::default()
        };
        for (fd, f) in img.fds.iter().enumerate() {
            let handle = match *f {
                azos_linux_rt::ExecFd::Closed => continue,
                azos_linux_rt::ExecFd::Console => MOVE_CONSOLE,
                azos_linux_rt::ExecFd::File(h) => h,
                azos_linux_rt::ExecFd::Pipe(tok) => {
                    match (sys::pipe::end_of(tok), fd) {
                        (Some(sys::pipe::End::Read), 0) | (Some(sys::pipe::End::Write), 1..) => {}
                        _ => return azos_abi::error::Errno::EINVAL.to_syscall_ret(),
                    }
                    match sys::pipe::region_of(tok) {
                        Ok((cap, _)) => cap,
                        Err(e) => return e as i64,
                    }
                }
            };
            let n = req.nmoves as usize;
            req.moves[n] = Move { child_fd: fd as u32, handle, perms: 0, _pad: 0 };
            req.nmoves += 1;
        }
        sys::spawn_ex(img.path, Some(&req)) as i64
    }
    fn resume_with_thread_pointer(&self, frame: &ForeignFrame, tp: u64) -> i64 {
        #[cfg(target_arch = "x86_64")]
        {
            successor::start(frame, tp)
        }
        // The thread pointer is a register ring 3 writes itself here: the
        // runtime is never asked.
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (frame, tp);
            azos_abi::error::Errno::ENOSYS.to_syscall_ret()
        }
    }
}

// arch-only: x86_64's `arch_prctl(ARCH_SET_FS)`; riscv64's `tp` and aarch64's
// `TPIDR_EL0` are written by the program itself.
#[cfg(target_arch = "x86_64")]
mod successor {
    use super::{sys, ForeignFrame};
    use azos_abi::syscall_nr::{SLEEP_RELATIVE, SYS_SLEEP_UNTIL, SYS_THREAD_CREATE};

    /// The successor's stack: used from its first instruction to its resume
    /// of the program, by one successor at a time (x86_64 has no Linux-thread
    /// rows yet: two threads of one program calling `arch_prctl(ARCH_SET_FS)`
    /// at once would share it).
    const STACK_BYTES: usize = 4096;
    #[repr(C, align(16))]
    struct Stack(core::cell::UnsafeCell<[u8; STACK_BYTES]>);
    // SAFETY: only the successor thread touches it, see above.
    unsafe impl Sync for Stack {}
    static STACK: Stack = Stack(core::cell::UnsafeCell::new([0; STACK_BYTES]));

    // The successor starts here with `rsp` at its stack's (aligned) top and
    // the frame in `rdx`: realign for a call and resume. A section of its
    // own, padded to 16 bytes: code the linker places after it (the runtime's
    // `_start`) keeps its alignment, and the kernel refuses an odd entry.
    core::arch::global_asm!(
        ".pushsection .text.lxrt_successor,\"ax\",@progbits",
        ".p2align 4",
        ".globl lxrt_successor_entry",
        "lxrt_successor_entry:",
        "    and rsp, -16",
        "    call lxrt_successor",
        "    ud2",
        ".p2align 4",
        ".popsection",
    );

    unsafe extern "C" {
        fn lxrt_successor_entry();
    }

    /// Start the successor of the calling thread with FS base `tp`, resuming
    /// `frame`, and park the caller for good; the native error when no thread
    /// could be made. The frame and the program's stack below it are the
    /// program's again the moment the successor runs, so nothing may touch
    /// the stack after the create: the park loop is registers only, and the
    /// parked thread is ended with the process (the successor's
    /// `exit_group`).
    pub(super) fn start(frame: &ForeignFrame, tp: u64) -> i64 {
        let top = STACK.0.get() as usize + STACK_BYTES;
        let r: i64;
        // SAFETY: SYS_THREAD_CREATE(entry, stack, arg = the frame, no
        // clear-tid word, tls); on success the loop never ends, so the
        // registers it rewrites are never read back. On failure only rax and
        // the call's clobbers changed.
        unsafe {
            core::arch::asm!(
                "syscall",
                "test rax, rax",
                "js 3f",
                "2:",
                "mov eax, {sleep}",
                "mov rdi, {hour}",
                "mov esi, {rel}",
                "syscall",
                "jmp 2b",
                "3:",
                sleep = const SYS_SLEEP_UNTIL,
                hour = const 3_600_000_000_000u64,
                rel = const SLEEP_RELATIVE,
                inlateout("rax") SYS_THREAD_CREATE as i64 => r,
                in("rdi") lxrt_successor_entry as *const () as usize as u64,
                in("rsi") top as u64,
                in("rdx") frame as *const ForeignFrame as u64,
                in("r10") 0u64,
                in("r8") tp,
                lateout("rcx") _, lateout("r11") _,
                options(nostack),
            );
        }
        r
    }

    /// The successor: resume the program's frame, which carries the call's
    /// result, on this thread and its FS base.
    ///
    /// # Safety
    /// `frame` is the frame of the trap [`start`] answered; the thread that
    /// took it never returns to user mode.
    #[unsafe(no_mangle)]
    unsafe extern "C" fn lxrt_successor(_zero: u64, _stack: u64, frame: *const ForeignFrame) -> ! {
        // SAFETY: as above.
        unsafe { sys::foreign_resume(frame) };
        sys::exit(121)
    }
}


/// What a Linux thread's creator leaves on the new stack for the thread's
/// first instructions: the registers to resume and the words to store its id in.
#[repr(C)]
struct ThreadStart {
    frame: ForeignFrame,
    settid: [u64; 2],
}

/// A Linux thread starts here (`SYS_THREAD_CREATE`'s entry: `(0, stack, start)`),
/// stores its id where `clone` asked and resumes the program on the creator's
/// registers with the result 0.
extern "C" fn lxrt_thread_start(_zero: u64, _stack: u64, start: u64) -> ! {
    // SAFETY: `Sys::thread_create` wrote the block at `start` before the
    // thread could run.
    let st = unsafe { &*(start as *const ThreadStart) };
    let tid = sys::getpid() as i32;
    for a in st.settid {
        if a != 0 {
            // SAFETY: the 32-bit words the program named in its `clone`.
            unsafe { core::ptr::write_volatile(a as *mut i32, tid) };
        }
    }
    // SAFETY: the frame is the creator's, copied.
    unsafe { sys::foreign_resume(&st.frame) };
    sys::exit(121)
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

// x86_64: `rsp` is the Linux initial stack, 16-byte aligned, and `rsi` the
// startup block, as the System V calling convention takes the first two
// arguments in `rdi` and `rsi`. A trap is entered with `rsp` = `rdi` = the
// frame (16-byte aligned), so the `call` leaves the stack as a callee expects.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".section .text._start,\"ax\",@progbits",
    ".globl _start",
    "_start:",
    "    mov rdi, rsp",    // rsi stays: the startup block
    "    call lxrt_start",
    "    ud2",
    ".globl lxrt_trap_entry",
    "lxrt_trap_entry:",
    "    call lxrt_trap",
    "    ud2",
);

// What a handler without `SA_RESTORER` returns to: `rt_sigreturn` (139 on the
// asm-generic ISAs). x86-64 has no handler frames here, so its stub is never
// entered.
#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".section .text.lxrt_sigreturn,\"ax\",@progbits",
    ".globl lxrt_sigreturn",
    "lxrt_sigreturn:",
    "    li a7, 139",
    "    ecall",
);
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".section .text.lxrt_sigreturn,\"ax\",@progbits",
    ".globl lxrt_sigreturn",
    "lxrt_sigreturn:",
    "    mov x8, #139",
    "    svc #0",
);
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".section .text.lxrt_sigreturn,\"ax\",@progbits",
    ".globl lxrt_sigreturn",
    "lxrt_sigreturn:",
    "    ud2",
);

unsafe extern "C" {
    /// The trap entry above.
    fn lxrt_trap_entry();
    /// `rt_sigreturn`'s trampoline.
    fn lxrt_sigreturn();
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
    // A pipe end the spawn shared arrives as a region: map it as the end its
    // fd position names (`azos_libsys::pipe::adopt_startup`).
    let mut fds = block.as_ref().map_or([azos_abi::ushell::StartupFd::default(); azos_abi::ushell::STARTUP_FDS], |b| b.fds);
    sys::pipe::adopt_startup(&mut fds);
    let given = block.as_ref().map(|_| Startup { fds: &fds, cwd });
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
    #[cfg(target_arch = "x86_64")]
    RT.dispatch_x86_64(f);
    #[cfg(not(target_arch = "x86_64"))]
    RT.dispatch(f);
    // SAFETY: the frame, with the result in it.
    unsafe { sys::foreign_resume(frame) };
    sys::exit(124)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(123)
}

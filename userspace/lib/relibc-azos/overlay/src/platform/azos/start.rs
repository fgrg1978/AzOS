// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Process entry and the main thread's TLS.
//!
//! The kernel starts an image with no stack of strings: `SYS_SPAWN_EX` leaves a
//! startup block (arguments, environment, working directory, descriptors) and
//! its address in the second argument register (`a1` / `x1` / `rsi`). relibc's
//! start code (`relibc_start_v1`) wants a System V stack: `argc`, `argv`,
//! `envp` and an auxiliary vector. `relibc_azos_start` reads the block through
//! `azos_libsys` and lays that stack out, with one auxiliary entry set that
//! matters: a program header for the `PT_TLS` segment, copied from the image's
//! own program headers (no linker script: lld maps the ELF and program headers
//! at the start of the read-only segment and names the ELF header
//! `__ehdr_start`).
//!
//! **x86_64 and the first thread.** Ring 3 cannot set its own FS base (CR4.FSGSBASE
//! is off and no call sets it), and relibc's TLS is addressed through it. The
//! kernel installs a thread pointer only at `SYS_THREAD_CREATE`, so on x86_64
//! the process's first thread builds the TCB, creates a second thread with it
//! as the thread pointer, and parks; the second thread starts relibc again from
//! the top (a TCB is then present, so it skips the allocation) and runs `main`.
//! The process is then a multi-thread group. The other two ISAs set `tp` /
//! `TPIDR_EL0` from ring 3. When the kernel enables FSGSBASE (`HWCAP_X86_FSGSBASE`)
//! this path becomes one `wrfsbase`.

// The entry, the thread pointer and the TLS layout are per ISA; on any other the
// build stops here instead of producing a process that cannot start.
#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("relibc azos start: no entry for this ISA (riscv64, aarch64, x86_64)");

use core::{ffi::c_int, ptr};

use crate::{
    header::sys_auxv::{AT_NULL, AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM},
    platform::types::c_char,
    start::relibc_start_v1,
};

unsafe extern "C" {
    /// The C program's entry.
    fn main(argc: isize, argv: *mut *mut c_char, envp: *mut *mut c_char) -> c_int;

    // The image's ELF header, which the linker defines in the read-only
    // segment it maps the headers in.
    static __ehdr_start: u8;
}

// The image's entry. One per ISA: pass the startup block (the second argument
// register) as the first argument and align the stack.
#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".globl _start",
    "_start:",
    "    mv a0, a1",
    "    andi sp, sp, -16",
    "    call relibc_azos_start",
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".globl _start",
    "_start:",
    "    mov x0, x1",
    "    mov x2, sp",
    "    and x2, x2, #-16",
    "    mov sp, x2",
    "    bl relibc_azos_start",
);

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl _start",
    ".type _start, @function",
    "_start:",
    "    mov rdi, rsi",
    "    xor ebp, ebp",
    "    and rsp, -16",
    "    call relibc_azos_start",
    "    ud2",
);

/// An ELF64 program header, as `ld_so` reads it.
#[repr(C)]
struct Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

const PT_TLS: u32 = 7;

/// argc, up to `MAX_ARGS` + `MAX_ENVS` pointers with their terminators, and the
/// auxiliary vector (four entries and the end). The spawn request bounds both
/// lists (`azos_abi::ushell`); an image the boot started has neither.
const MAX_ARGS: usize = azos_abi::ushell::SPAWN_ARGC_MAX;
const MAX_ENVS: usize = azos_abi::ushell::SPAWN_ENVC_MAX;
const STACK_WORDS: usize = 1 + MAX_ARGS + 1 + MAX_ENVS + 1 + 2 * 5;

static mut STACK: [usize; STACK_WORDS] = [0; STACK_WORDS];
static mut TLS_PHDR: Phdr =
    Phdr { p_type: PT_TLS, p_flags: 4, p_offset: 0, p_vaddr: 0, p_paddr: 0, p_filesz: 0, p_memsz: 0, p_align: 0 };

/// The image's `PT_TLS` program header, read through `__ehdr_start`.
///
/// # Safety
/// The ELF and program headers are mapped (the first read-only segment).
unsafe fn image_tls() -> Option<Phdr> {
    let ehdr = ptr::addr_of!(__ehdr_start);
    // ELF64: `e_phoff` at 32, `e_phentsize` at 54, `e_phnum` at 56.
    let phoff = unsafe { ptr::read_unaligned(ehdr.add(32).cast::<u64>()) } as usize;
    let phentsize = unsafe { ptr::read_unaligned(ehdr.add(54).cast::<u16>()) } as usize;
    let phnum = unsafe { ptr::read_unaligned(ehdr.add(56).cast::<u16>()) } as usize;
    if phentsize != core::mem::size_of::<Phdr>() {
        return None;
    }
    (0..phnum)
        .map(|i| unsafe { ptr::read_unaligned(ehdr.add(phoff + i * phentsize).cast::<Phdr>()) })
        .find(|p| p.p_type == PT_TLS)
}

/// The System V process stack `relibc_start_v1` expects, built from the
/// startup block.
///
/// # Safety
/// Once, on the first thread, before anything else runs.
unsafe fn build_stack() -> &'static crate::start::Stack<'static> {
    let argc = azos_libsys::argc().min(MAX_ARGS);
    let stack = unsafe { &mut *ptr::addr_of_mut!(STACK) };
    let mut w = 0;
    let mut put = |v: usize| {
        stack[w] = v;
        w += 1;
    };
    // An image started without a block has no name for itself.
    static EMPTY: [u8; 1] = [0];
    put(argc.max(1));
    if argc == 0 {
        put(EMPTY.as_ptr() as usize);
    }
    for i in 0..argc {
        put(azos_libsys::arg(i).map_or(EMPTY.as_ptr() as usize, |a| a.as_ptr() as usize));
    }
    put(0);
    for i in 0..MAX_ENVS {
        match azos_libsys::env_at(i) {
            Some(e) => put(e.as_ptr() as usize),
            None => break,
        }
    }
    put(0);
    // The template of the first thread's TLS, as a one-entry program header
    // table: the image's own `PT_TLS` (none: an empty template).
    let phdr = unsafe { &mut *ptr::addr_of_mut!(TLS_PHDR) };
    if let Some(tls) = unsafe { image_tls() } {
        *phdr = tls;
    }
    for (k, v) in [
        (AT_PHDR, ptr::from_mut(phdr) as usize),
        (AT_PHENT, core::mem::size_of::<Phdr>()),
        (AT_PHNUM, 1),
        (AT_PAGESZ, azos_libsys::PAGE_SIZE),
        (AT_NULL, 0),
    ] {
        put(k);
        put(v);
    }
    // SAFETY: `Stack` is a view of the words just written, `argc` first.
    unsafe { &*ptr::addr_of!(STACK).cast::<crate::start::Stack<'static>>() }
}

/// First Rust code of a process.
///
/// # Safety
/// Called once, by `_start`, with the startup block's address (or 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn relibc_azos_start(startup_block: usize) -> ! {
    azos_libsys::startup_init(startup_block);
    let sp = unsafe { build_stack() };
    // arch-only: x86_64 cannot set its own FS base; the other ISAs set the thread pointer from ring 3.
    #[cfg(target_arch = "x86_64")]
    first_thread::START_SP.store(ptr::from_ref(sp) as usize, core::sync::atomic::Ordering::Release);
    unsafe { relibc_start_v1(sp, main) }
}

/// Runs inside `relibc_start_v1`, after TLS is up: the state that needs the
/// allocator.
pub(crate) unsafe fn init() {
    super::fdtab::init_stdio();
}

// ── the thread pointer ───────────────────────────────────────────────────────

/// The calling (first) thread's thread pointer; 0 if TLS is not set up yet.
pub fn thread_pointer() -> usize {
    let tp: usize;
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("mv {}, tp", out(reg) tp, options(nomem, nostack));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) tp, options(nomem, nostack));
    }
    // FS cannot be read without a valid base: whether it is set is known here.
    #[cfg(target_arch = "x86_64")]
    {
        tp = usize::from(first_thread::TLS_THREAD.load(core::sync::atomic::Ordering::Acquire));
    }
    tp
}

/// Install TLS on this thread (`Tcb::activate`): `tls_end` is the end of the
/// static TLS block, where the TCB starts; `tls_len` its size.
///
/// # Safety
/// `tls_end - tls_len` .. `tls_end` is the thread's TLS, copied from its template.
pub(crate) unsafe fn activate_tls(tls_end: usize, tls_len: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        // Uses the ABI page below the TLS: the pointer to the TCB at its end.
        let abi_ptr = tls_end - tls_len - 16;
        unsafe {
            ptr::write(abi_ptr as *mut usize, tls_end);
            core::arch::asm!("msr tpidr_el0, {}", in(reg) abi_ptr, options(nostack));
        }
    }
    #[cfg(target_arch = "riscv64")]
    {
        // `tp` points at the static TLS; the word below it is the TCB pointer.
        let tls_start = tls_end - tls_len;
        unsafe {
            ptr::write((tls_start - 8) as *mut usize, tls_end);
            core::arch::asm!("mv tp, {}", in(reg) tls_start, options(nostack));
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        let _ = tls_len;
        // Threads made by `rlct_clone` already have their base; the first thread
        // moves to one (see the module comment).
        if !first_thread::TLS_THREAD.load(core::sync::atomic::Ordering::Acquire) {
            unsafe { first_thread::move_to_tls_thread(tls_end) }
        }
    }
}

// ── x86_64: the first thread moves to a thread with a TLS base ────────────────

// arch-only: x86_64 cannot set its own FS base; the other ISAs set the thread
// pointer from ring 3.
#[cfg(target_arch = "x86_64")]
mod first_thread {
    use core::{
        ptr,
        sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    };

    use super::{main, relibc_start_v1};
    use crate::platform::{
        sys::{errno_of, Sys},
        Pal,
    };
    use crate::header::sys_mman::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};

    /// Set once a thread with an FS base runs `relibc_start_v1` (the second pass).
    pub(super) static TLS_THREAD: AtomicBool = AtomicBool::new(false);

    /// The stack of the startup block's words, for the second pass.
    pub(super) static START_SP: AtomicUsize = AtomicUsize::new(0);

    /// Parking word of the first thread.
    static PARKED: AtomicU32 = AtomicU32::new(0);

    /// Bytes of the second thread's stack: what the kernel gave the first one
    /// (Kconfig `USER_STACK_SIZE_KB`, passed by the Makefile).
    const MAIN_STACK_BYTES: usize = match option_env!("AZOS_USER_STACK_BYTES") {
        Some(s) => parse(s.as_bytes()),
        None => 16 * 1024,
    };

    const fn parse(s: &[u8]) -> usize {
        let (mut v, mut i) = (0, 0);
        while i < s.len() {
            v = v * 10 + (s[i] - b'0') as usize;
            i += 1;
        }
        v
    }

    extern "C" fn second_pass(_zero: u64, _sp: u64, _arg: u64) -> ! {
        TLS_THREAD.store(true, Ordering::Release);
        // SAFETY: the same stack and entry as the first pass; a TCB is current now.
        unsafe {
            let sp = &*(START_SP.load(Ordering::Acquire) as *const crate::start::Stack<'static>);
            relibc_start_v1(sp, main)
        }
    }

    /// # Safety
    /// Called from `Tcb::activate` on the first thread, with its TCB complete.
    pub(super) unsafe fn move_to_tls_thread(tls_end: usize) -> ! {
        let stack = unsafe {
            Sys::mmap(ptr::null_mut(), MAIN_STACK_BYTES, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)
        };
        let Ok(base) = stack else { azos_libsys::exit(127) };
        let top = (base as usize + MAIN_STACK_BYTES) & !15;
        let rc = azos_libsys::thread_create_with_tls(second_pass, top, 0, ptr::null_mut(), tls_end as u64);
        if rc < 0 {
            let _ = errno_of(rc);
            azos_libsys::exit(127);
        }
        // This thread has nothing left to do; the process ends when the second one exits.
        loop {
            azos_libsys::futex_wait(&PARKED, 0, 0);
        }
    }
}

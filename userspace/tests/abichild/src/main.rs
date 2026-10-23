// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The processes `abitest` starts to watch them live and die.
//!
//! A native process is created by `SYS_SPAWN_EX` and by nothing else, so a
//! test that needs a child (to be waited on, killed by a fault, orphaned,
//! reaped, listed in the kernel's task list) needs an image to start. This is that
//! image: `argv[1]` names what the process does and the rest of `argv` are its
//! parameters (decimal text, a name). Each mode is one behaviour the parent
//! checks from outside: how it ended (its exit code, `128 + signal` for a
//! fault), what it left behind, who adopted what it started.
//!
//! The image has a row of its own (`ABICHILD.ELF`, QEMU test topologies only):
//! the right to start itself, which the process-tree modes (`orphan-mid`,
//! `subreaper`) use, and the task list they watch it by (the
//! task view and the introspection regions).
//!
//! Modes, with the parent's check in `userspace/tests/abitest`:
//!
//! * `exit N` - exits with N (`wait`, `waitpid`, `wait_status`, the zombie
//!   notices, the exit storm).
//! * `fault-udf`, `fault-null` - an undefined instruction, a store through
//!   NULL: killed alone, the parent told `128 + SIGILL` / `128 + SIGSEGV`.
//! * `touch PAGES CODE` - grows its break, writes every page, exits with CODE
//!   (the memory it held comes back at its exit).
//! * `nap MS` - a process that lives MS milliseconds.
//! * `storm-spin`, `storm-fault`, `threads-exit` - a process whose threads
//!   spin or fault while its exit stops them all.
//! * `store-code`, `store-rodata`, `read-into-code`, `call-rodata`,
//!   `mmap-ro`, `mmap-none` - the memory permissions the loader and `mmap`
//!   promise (W^X, read-only data not executable, `prot` honoured).
//! * `udp-server IP PORT` - answers one datagram.
//! * `foreign` - registers a foreign-ABI trap entry and runs a program that
//!   traps three times.
//! * `orphan-mid WANT`, `orphan-leaf WANT`, `subreaper` - the re-parenting of
//!   orphans to init or to a subreaper. Once adopted, the orphan waits for its
//!   adopter's stop request (`task_kill`, sent after it listed the orphan):
//!   a request ends its futex wait with `-EINTR`. No capability carries the
//!   release (one passed through the intermediate parent would be revoked
//!   by that parent's exit) and no timing assumption stands in for "listed";
//!   the wait's ceiling only ends a stuck adopter.

#![no_std]
#![no_main]

#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("abichild: the fault, foreign-program and register-index arms know riscv64, aarch64 and x86_64: a new ISA names them here");

use azos_libsys as sys;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering as AO};

// Each program uses the half of it the other does not.
#[allow(dead_code)]
#[path = "shared.rs"]
mod shared;
use shared::*;

/// Code an orphan exits with when it saw itself adopted by `want`.
const ORPHAN_ADOPTED: i32 = 0x5A;
/// ... and when it did not, within the deadline.
const ORPHAN_NOT_ADOPTED: i32 = 0x5B;
#[no_mangle]
pub extern "C" fn _start(_a0: usize, a1: usize) -> ! {
    sys::startup_init(a1);
    let mode = sys::arg(1).unwrap_or(b"");
    let arg = |i: usize| sys::arg(i).unwrap_or(b"");
    let num = |i: usize| parse_dec(arg(i)).unwrap_or(0);
    match mode {
        b"exit" => sys::exit(num(2) as i32),
        b"fault-udf" => fault_udf(),
        b"fault-null" => {
            unsafe { core::ptr::write_volatile(0x10 as *mut u32, 1) };
            sys::exit(0)
        }
        b"touch" => touch(num(2) as usize, num(3) as i32),
        b"nap" => {
            sys::sleep(num(2));
            sys::exit(0)
        }
        b"storm-spin" => {
            spawn_thread(t_spin, 0);
            spawn_thread(t_spin, 1);
            sys::sleep(1);
            sys::exit(7)
        }
        b"storm-fault" => {
            spawn_thread(t_spin, 0);
            spawn_thread(t_null_store, 1);
            sys::exit(7)
        }
        b"threads-exit" => {
            spawn_thread(t_spin, 0);
            sys::sleep(5);
            sys::exit(7)
        }
        b"store-code" => {
            unsafe { core::ptr::write_volatile(store_code as fn() as usize as *mut u8, 0x00) };
            sys::exit(0x77)
        }
        b"store-rodata" => {
            let ro = core::hint::black_box(&RO_WORD as *const u64 as usize);
            unsafe { core::ptr::write_volatile(ro as *mut u8, 0x00) };
            sys::exit(0x77)
        }
        b"read-into-code" => read_into_code(),
        b"call-rodata" => call_rodata(),
        b"mmap-ro" => mmap_store(sys::PROT_READ),
        b"mmap-none" => mmap_store(0),
        b"udp-server" => udp_server(num(2) as u32, num(3) as u16),
        b"foreign" => foreign(),
        b"orphan-mid" => {
            let pid = spawn_child(&[b"orphan-leaf", arg(2)]);
            sys::exit(if pid > 0 { 0 } else { 1 })
        }
        b"orphan-leaf" => orphan_leaf(num(2) as u32),
        b"subreaper" => subreaper(),
        b"ioport" => ioport(arg(2)),
        _ => sys::exit(99),
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    sys::exit(2)
}

/// Ring-3 port I/O (x86_64; `abitest`'s `check_ioports`). This row holds
/// one port, the POST port 0x80 (`ioport.128.1`, QEMU topologies). `granted`:
/// open it and read it, exit 0. `stray`: open it, then read port 0x84, which
/// no range opens: the #GP kills the child (139); 3 if the read ran. `closed`:
/// read 0x80 without opening it: killed the same way, 3 if it ran. `revoked`:
/// open it and read it, close its capability, read it again: killed the
/// same way (the close took the port back), 3 if the second read ran, 5 if
/// the close was refused. 4: the open was refused. Reads only, and of ports
/// with nothing behind them on QEMU, so a check that fails to fault changes
/// no device.
fn ioport(which: &[u8]) -> ! {
    const POST: u16 = 0x80;
    const STRAY: u16 = 0x84;
    match which {
        b"revoked" => {
            let Ok(io) = sys::ioport_open(POST, 1) else { sys::exit(4) };
            core::hint::black_box(io.inb(POST));
            if sys::ioport_close(io) != 0 {
                sys::exit(5);
            }
            // The range is closed: the bare instruction (the `IoPorts` went
            // with the close).
            #[cfg(target_arch = "x86_64")]
            unsafe {
                core::arch::asm!("in al, dx", in("dx") POST, out("al") _, options(nomem, nostack));
            }
            // No port space: the open above already refused (abitest asks only on x86_64).
            #[cfg(not(target_arch = "x86_64"))]
            sys::exit(99);
            #[allow(unreachable_code)]
            sys::exit(3)
        }
        b"granted" | b"stray" => {
            let Ok(io) = sys::ioport_open(POST, 1) else { sys::exit(4) };
            let port = if which == b"granted" { POST } else { STRAY };
            core::hint::black_box(io.inb(port));
            sys::exit(if which == b"granted" { 0 } else { 3 })
        }
        b"closed" => {
            // A port this thread never opened: the bare instruction (an
            // `IoPorts` exists only for an open range).
            #[cfg(target_arch = "x86_64")]
            unsafe {
                core::arch::asm!("in al, dx", in("dx") POST, out("al") _, options(nomem, nostack));
            }
            // No port space: nothing to probe (abitest asks only on x86_64).
            #[cfg(not(target_arch = "x86_64"))]
            sys::exit(99);
            #[allow(unreachable_code)]
            sys::exit(3)
        }
        _ => sys::exit(99),
    }
}

fn fault_udf() -> ! {
    unsafe {
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("udf #0");
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!("unimp");
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("ud2");
    }
    sys::exit(0)
}

/// Map `pages` pages one at a time, write one byte in each that was granted,
/// exit with `code`. Mapped, not a `static`: a bss array would be mapped at
/// load and charged to the row's budget, which is not what the parent
/// measures.
fn touch(pages: usize, code: i32) -> ! {
    for _ in 0..pages {
        let a = sys::mmap(0, sys::PAGE_SIZE as u64, sys::PROT_READ | sys::PROT_WRITE, 0, sys::MAP_ANON_FD, 0);
        if a <= 0 {
            break;
        }
        unsafe { core::ptr::write_volatile(a as *mut u8, 1) };
    }
    sys::exit(code)
}

// ── Threads ─────────────────────────────────────────────────────────────────

#[repr(C, align(16))]
struct Stack([u8; 4096]);
static mut STACKS: [Stack; 2] = [const { Stack([0; 4096]) }; 2];
static SPIN: AtomicU64 = AtomicU64::new(0);

/// Start thread `entry` on stack `i`. A thread that cannot be made ends the
/// process with a code the parent's check names.
fn spawn_thread(entry: sys::ThreadEntry, i: usize) {
    let top = core::ptr::addr_of_mut!(STACKS) as usize + (i + 1) * core::mem::size_of::<Stack>();
    if sys::thread_create(entry, top, 0, core::ptr::null_mut()) <= 0 {
        sys::exit(3);
    }
}

/// Spin forever: only its process's exit ends it.
extern "C" fn t_spin(_z: u64, _stack: u64, _arg: u64) -> ! {
    loop {
        SPIN.fetch_add(1, AO::Relaxed);
    }
}

/// A thread that faults at once (a store through a null pointer): its fault
/// ends its whole process.
extern "C" fn t_null_store(_z: u64, _stack: u64, _arg: u64) -> ! {
    unsafe { core::ptr::write_volatile(0x8 as *mut u32, 1) };
    sys::thread_exit(0)
}

// ── Memory permissions ──────────────────────────────────────────────────────

static RO_WORD: u64 = 0x5752_5f4f_5f4e_4c59; // in .rodata

/// A function whose first byte `store-code` overwrites.
#[inline(never)]
fn store_code() {}

/// `read()` into this process's own code: the kernel's write is refused the
/// way the process's store is, because code is not writable. Exits 0 when the
/// read was refused.
fn read_into_code() -> ! {
    let code = store_code as fn() as usize;
    let f = sys::open_root(sys::cstr!(b"/fat/CONFIG.INI"), 0);
    let code_buf = unsafe { core::slice::from_raw_parts_mut(code as *mut u8, 1) };
    let r = if f >= 0 { sys::read(f as u64, code_buf) } else { -1 };
    sys::exit(if f >= 0 && r < 0 { 0 } else { 1 })
}

/// Call a `ret` held in `.rodata`: read-only data is never executable, so the
/// process dies at the first fetch.
fn call_rodata() -> ! {
    #[cfg(target_arch = "riscv64")]
    static RET: [u32; 1] = [0x0000_8067]; // jalr x0, 0(ra)
    #[cfg(target_arch = "aarch64")]
    static RET: [u32; 1] = [0xd65f_03c0]; // ret
    #[cfg(target_arch = "x86_64")]
    static RET: [u32; 1] = [0x0000_00c3]; // ret (one byte, c3)
    let ro = core::hint::black_box(RET.as_ptr() as usize);
    // SAFETY: the point of the mode; on a correct kernel the call faults at
    // its first fetch and never returns.
    let f: extern "C" fn() = unsafe { core::mem::transmute(ro) };
    f();
    sys::exit(0x66)
}

/// Map a page with `prot` and store to it: a store to a `PROT_READ` or
/// `PROT_NONE` mapping faults.
fn mmap_store(prot: u64) -> ! {
    let m = sys::mmap(0, 4096, prot, 0, sys::MAP_ANON_FD, 0);
    if m <= 0 {
        sys::exit(2);
    }
    unsafe { core::ptr::write_volatile(m as *mut u8, 1) };
    sys::exit(0x77)
}

// ── UDP ─────────────────────────────────────────────────────────────────────

/// Answer the first datagram that reaches port `port` of address `ip` with
/// "pong" to whoever wrote it, without knowing in advance who that is.
fn udp_server(ip: u32, port: u16) -> ! {
    const REPLY: &[u8] = b"pong";
    let s = sys::socket_typed(2, 2, 0);
    if s < 0 {
        sys::exit(1);
    }
    if sys::bind_typed(s as u32, &sys::sockaddr_in(ip.to_be_bytes(), port)) != 0 {
        sys::exit(1);
    }
    let mut buf = [0u8; 32];
    let mut sender = [0u8; sys::SOCKADDR_LEN];
    let mut deadline = Deadline::in_ms(30_000);
    while !deadline.expired() {
        let n = sys::recvfrom_typed(s as u32, &mut buf, Some(&mut sender));
        if n > 0 {
            let _ = sys::sendto_typed(s as u32, REPLY, Some(&sender));
            break;
        }
        sys::yield_now();
    }
    sys::exit(0)
}

// ── Orphans ─────────────────────────────────────────────────────────────────

/// How long an adopted orphan waits for its adopter's stop request: a
/// ceiling for a stuck adopter, never a wait the test needs.
const ORPHAN_CEILING_NS: u64 = 30_000_000_000;

/// The word the orphan waits on; nothing ever wakes or changes it, only the
/// adopter's stop request ends the wait.
static ORPHAN_GATE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The grandchild of an orphan test. It waits (clock deadline) until the
/// task list shows its parent as `want`, then stays alive until the
/// adopter has listed it and asked it to stop (see the header), and exits
/// [`ORPHAN_ADOPTED`]; [`ORPHAN_NOT_ADOPTED`] at the deadline.
fn orphan_leaf(want: u32) -> ! {
    let me = sys::getpid() as u32;
    let mut deadline = Deadline::in_ms(5_000);
    while !deadline.expired() {
        if parent_of(me) == want {
            // `-EINTR` once the adopter asked this task to stop (sticky, so a
            // request that came before the wait is seen too).
            let _ = sys::futex_wait(&ORPHAN_GATE, 0, ORPHAN_CEILING_NS);
            sys::exit(ORPHAN_ADOPTED);
        }
        sys::sleep(5);
    }
    sys::exit(ORPHAN_NOT_ADOPTED)
}

/// A subreaper: marks itself, starts a child that starts the orphan and
/// exits, and checks that the orphan came to it and not to init. Exits with a
/// bit per failed step (0: all held).
fn subreaper() -> ! {
    let sme = sys::getpid() as u32;
    let mut bad = 0i32;
    if sys::task_subreaper(sys::SUBREAPER_SET) != 1 { bad |= 1; }
    let mut sme_dec = [0u8; 20];
    let want = dec(sme as u64, &mut sme_dec);
    let mid = spawn_child(&[b"orphan-mid", want]);
    if mid <= 0 { sys::exit(bad | 2); }
    let (got, st) = reap_by_tid(mid);
    if got != mid || st != 0 { bad |= 4; }
    let orphan = only_child_of(sme);
    if orphan == 0 { bad |= 8; }
    if orphan != 0 {
        // Listed: let it go.
        if sys::task_kill(orphan, sys::KILL_REQUEST, 1, 0) < 1 { bad |= 128; }
        let (got, st) = reap_by_tid(orphan as isize);
        if got != orphan as isize { bad |= 16; }
        if st != ORPHAN_ADOPTED { bad |= 32; }
    }
    if sys::task_subreaper(sys::SUBREAPER_CLEAR) != 0 { bad |= 64; }
    sys::exit(bad)
}

// ── The foreign-ABI family (D6, `azos_abi::foreign`) ─────────────────────────
//
// The process registers a trap entry and resumes into a tiny "foreign
// program" (assembly, on a stack of its own) that makes three traps. Each
// trap must be reflected to the entry, with the program's registers in the
// frame; the entry answers and resumes. The program keeps a value in one
// register the whole time and uses the first answer in the second trap, so a
// register lost by the reflect or by the resume shows. On x86_64 the first
// answer also sets rcx and r11, the two registers `syscall` itself clobbers,
// and the program copies them for the second trap to report: a resume must
// hand the thread the runtime's values, not the RIP and RFLAGS the lean
// `sysret` path leaves there (K1 M1). The process exits 0 when the whole
// conversation held, else with the number of the step that did not.

type Frame = sys::foreign_abi::ForeignFrame;
const REG_NUMBER: usize = sys::foreign_abi::REG_NUMBER;
const REG_RESULT: usize = sys::foreign_abi::REG_RESULT;
const REG_FIRST_ARG: usize = sys::foreign_abi::REG_FIRST_ARG;
const REG_SP: usize = sys::foreign_abi::REG_SP;

/// The foreign program's trap numbers, and the answer to the first.
const FOREIGN_CALL_A: u64 = 0x7001;
const FOREIGN_CALL_B: u64 = 0x7002;
const FOREIGN_CALL_DONE: u64 = 0x7003;
const FOREIGN_ARG: u64 = 20;
const FOREIGN_KEEP: u64 = 0x1234;

/// Index in the frame of the register the program keeps across its traps
/// (`KEEP`) and the one it copies the first answer into (`COPY`).
#[cfg(target_arch = "riscv64")]
const FOREIGN_KEEP_REG: usize = 9; // s1
#[cfg(target_arch = "riscv64")]
const FOREIGN_COPY_REG: usize = 18; // s2
#[cfg(target_arch = "aarch64")]
const FOREIGN_KEEP_REG: usize = 19;
#[cfg(target_arch = "aarch64")]
const FOREIGN_COPY_REG: usize = 20;
#[cfg(target_arch = "x86_64")]
const FOREIGN_KEEP_REG: usize = 3; // rbx
#[cfg(target_arch = "x86_64")]
const FOREIGN_COPY_REG: usize = 12; // r12
/// x86_64: the frame indices of rcx and r11 (the first answer sets them),
/// and of r13 and r14 (the program's copies, reported by the second trap).
#[cfg(target_arch = "x86_64")]
const FOREIGN_RCX_REG: usize = 1;
#[cfg(target_arch = "x86_64")]
const FOREIGN_R11_REG: usize = 11;
#[cfg(target_arch = "x86_64")]
const FOREIGN_RCX_COPY_REG: usize = 13;
#[cfg(target_arch = "x86_64")]
const FOREIGN_R11_COPY_REG: usize = 14;
#[cfg(target_arch = "x86_64")]
const FOREIGN_RCX: u64 = 0x5a5a_0001;
#[cfg(target_arch = "x86_64")]
const FOREIGN_R11: u64 = 0x5a5a_0002;

static FOREIGN_STEP: AtomicU32 = AtomicU32::new(0);

// The foreign program and the runtime's trap entry. The entry is reached with
// the frame's address in the first argument register and as the stack pointer.
#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".globl foreign_probe_prog",
    "foreign_probe_prog:",
    "    li s1, 0x1234",
    "    li a0, 20",
    "    li a7, 0x7001",
    "    ecall",
    "    mv s2, a0",
    "    li a7, 0x7002",
    "    ecall",
    "    li a7, 0x7003",
    "    ecall",
    "1:  j 1b",
    ".globl foreign_probe_entry",
    "foreign_probe_entry:",
    "    call foreign_probe_handler",
);
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".globl foreign_probe_prog",
    "foreign_probe_prog:",
    "    mov x19, #0x1234",
    "    mov x0, #20",
    "    mov x8, #0x7001",
    "    svc #0",
    "    mov x20, x0",
    "    mov x8, #0x7002",
    "    svc #0",
    "    mov x8, #0x7003",
    "    svc #0",
    "1:  b 1b",
    ".globl foreign_probe_entry",
    "foreign_probe_entry:",
    "    bl foreign_probe_handler",
);
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl foreign_probe_prog",
    "foreign_probe_prog:",
    "    mov ebx, 0x1234",
    "    mov edi, 20",
    "    mov eax, 0x7001",
    "    syscall",
    "    mov r12, rax",
    "    mov r13, rcx",
    "    mov r14, r11",
    "    mov eax, 0x7002",
    "    syscall",
    "    mov eax, 0x7003",
    "    syscall",
    "1:  jmp 1b",
    ".globl foreign_probe_entry",
    "foreign_probe_entry:",
    "    call foreign_probe_handler",
);

unsafe extern "C" {
    fn foreign_probe_prog();
    fn foreign_probe_entry();
}

/// The runtime's side: answer one reflected trap and resume, or end the process.
#[unsafe(no_mangle)]
unsafe extern "C" fn foreign_probe_handler(frame: *mut Frame) -> ! {
    // SAFETY: the frame the kernel pushed on this stack.
    let f = unsafe { &mut *frame };
    let num = f.gpr[REG_NUMBER];
    let step = FOREIGN_STEP.fetch_add(1, AO::Relaxed);
    match (step, num) {
        (0, FOREIGN_CALL_A) => {
            // The argument, and the register the program keeps, arrived whole.
            let arg = f.gpr[REG_FIRST_ARG];
            if arg != FOREIGN_ARG || f.gpr[FOREIGN_KEEP_REG] != FOREIGN_KEEP {
                sys::exit(11);
            }
            f.gpr[REG_RESULT] = arg * 2 + 1;
            #[cfg(target_arch = "x86_64")]
            {
                f.gpr[FOREIGN_RCX_REG] = FOREIGN_RCX;
                f.gpr[FOREIGN_R11_REG] = FOREIGN_R11;
            }
            // riscv64/aarch64: no register is clobbered by the trap itself, so
            // there is no scratch pair to answer.
            #[cfg(not(target_arch = "x86_64"))]
            {}
        }
        (1, FOREIGN_CALL_B) => {
            // The answer to the first trap, and the kept register, came back.
            if f.gpr[FOREIGN_COPY_REG] != FOREIGN_ARG * 2 + 1 || f.gpr[FOREIGN_KEEP_REG] != FOREIGN_KEEP {
                sys::exit(12);
            }
            // x86_64: the resume gave the program the rcx and r11 asked for.
            #[cfg(target_arch = "x86_64")]
            if f.gpr[FOREIGN_RCX_COPY_REG] != FOREIGN_RCX || f.gpr[FOREIGN_R11_COPY_REG] != FOREIGN_R11 {
                sys::exit(17);
            }
            #[cfg(not(target_arch = "x86_64"))]
            {}
            f.gpr[REG_RESULT] = 0;
        }
        (2, FOREIGN_CALL_DONE) => sys::exit(0),
        _ => sys::exit(13),
    }
    // SAFETY: the frame, with the result in it.
    unsafe { sys::foreign_resume(frame) };
    sys::exit(14)
}

fn foreign() -> ! {
    // A stack for the foreign program, and the frame it starts with: its
    // program counter and stack pointer, every other register zero.
    #[repr(C, align(16))]
    struct ProbeStack {
        _bytes: [u8; 4096],
    }
    static mut PROBE_STACK: ProbeStack = ProbeStack { _bytes: [0; 4096] };

    let rc = sys::foreign_entry(foreign_probe_entry as *const () as usize as u64);
    if rc != 0 {
        sys::exit(10);
    }
    let mut f = Frame::ZERO;
    f.pc = foreign_probe_prog as *const () as usize as u64;
    // The address of a static nothing else uses.
    f.gpr[REG_SP] = core::ptr::addr_of_mut!(PROBE_STACK) as u64 + 4096;
    // SAFETY: a frame that starts the program above on its own stack.
    let rc = unsafe { sys::foreign_resume(&f) };
    sys::exit(if rc < 0 { 15 } else { 16 })
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The processes `abitest` starts to watch them live and die.
//!
//! A native process is created by `SYS_SPAWN_EX` and by nothing else, so a
//! test that needs a child (to be waited on, killed by a fault, orphaned,
//! reaped, counted in `/proc/tasks`) needs an image to start. This is that
//! image: `argv[1]` names what the process does and the rest of `argv` are its
//! parameters (decimal text, a name). Each mode is one behaviour the parent
//! checks from outside: how it ended (its exit code, `128 + signal` for a
//! fault), what it left behind, who adopted what it started.
//!
//! The image has a row of its own (`ABICHILD.ELF`, QEMU test topologies only):
//! no capability but the right to start itself, which the process-tree modes
//! (`tree`, `orphan-mid`, `subreaper`) use.
//!
//! Modes, with the parent's check in `userspace/tests/abitest`:
//!
//! * `exit N` - exits with N (`wait`, `waitpid`, `wait_status`, the zombie
//!   notices, the exit storm).
//! * `fault-udf`, `fault-null` - an undefined instruction, a store through
//!   NULL: killed alone, the parent told `128 + SIGILL` / `128 + SIGSEGV`.
//! * `touch PAGES CODE` - grows its break, writes every page, exits with CODE
//!   (the memory it held comes back at its exit).
//! * `name NAME` - registers the service name NAME and exits (the name goes
//!   with the task).
//! * `nb-fill`, `nb-read` - non-blocking pipes that outlive their owner.
//! * `nap MS`, `tree` - a process that lives MS milliseconds; one that starts
//!   such a child of its own and reaps it (`/proc/tasks` shows a process its
//!   descendants and nothing else).
//! * `storm-spin`, `storm-fault`, `threads-exit` - a process whose threads
//!   spin or fault while its exit stops them all.
//! * `hidden PATH` - opens PATH; exits 0 if that failed.
//! * `store-code`, `store-rodata`, `read-into-code`, `call-rodata`,
//!   `mmap-ro`, `mmap-none` - the memory permissions the loader and `mmap`
//!   promise (W^X, read-only data not executable, `prot` honoured).
//! * `udp-server IP PORT` - answers one datagram.
//! * `foreign` - registers a foreign-ABI trap entry and runs a program that
//!   traps three times.
//! * `orphan-mid WANT NAME`, `orphan-leaf WANT NAME`, `subreaper NAME` - the
//!   re-parenting of orphans to init or to a subreaper.

#![no_std]
#![no_main]

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
        b"name" => register_name(arg(2)),
        b"nb-fill" => nb_fill(),
        b"nb-read" => nb_read(),
        b"nap" => {
            sys::sleep(num(2));
            sys::exit(0)
        }
        b"tree" => tree(),
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
        b"hidden" => {
            let mut path = [0u8; 32];
            let p = arg(2);
            if p.len() >= path.len() {
                sys::exit(2);
            }
            path[..p.len()].copy_from_slice(p);
            let fd = sys::open(&path[..p.len() + 1], 0);
            sys::exit(if fd < 0 { 0 } else { 1 })
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
            let want = arg(2);
            let name = arg(3);
            let pid = spawn_child(&[b"orphan-leaf", want, name]);
            sys::exit(if pid > 0 { 0 } else { 1 })
        }
        b"orphan-leaf" => orphan_leaf(num(2) as u32, arg(3)),
        b"subreaper" => subreaper(arg(2)),
        _ => sys::exit(99),
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    sys::exit(2)
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

/// Grow the break by `pages`, write one byte in each, exit with `code`. A
/// break, not a `static`: a bss array would be mapped at load and charged to
/// the row's budget, which is not what the parent measures.
fn touch(pages: usize, code: i32) -> ! {
    let base = sys::brk(0);
    if base > 0 {
        let top = sys::brk((base + (pages * sys::PAGE_SIZE) as isize) as u64);
        let mut a = base;
        while a + sys::PAGE_SIZE as isize <= top {
            unsafe { core::ptr::write_volatile(a as *mut u8, 1) };
            a += sys::PAGE_SIZE as isize;
        }
    }
    sys::exit(code)
}

fn register_name(name: &[u8]) -> ! {
    let mut buf = [0u8; 48];
    if name.len() >= buf.len() {
        sys::exit(2);
    }
    buf[..name.len()].copy_from_slice(name);
    let rc = sys::service_register(&buf[..name.len() + 1], 0, 0);
    sys::exit(if rc == 0 { 0 } else { 1 })
}

/// Pipes each `nb-fill` process creates, at most.
const NONBLOCK_FILL_PER_CHILD: usize = 8;

/// Create `PIPE_NONBLOCK` pipes and exit holding them; the exit code is how
/// many were made.
fn nb_fill() -> ! {
    let mut n = 0;
    while n < NONBLOCK_FILL_PER_CHILD {
        let mut p = [0u32; 2];
        if sys::pipe_typed(&mut p, sys::PIPE_NONBLOCK) != 0 {
            break;
        }
        n += 1;
    }
    sys::exit(n as i32)
}

/// Read one's own empty `PIPE_NONBLOCK` pipe: 0 when the read answers
/// `-EAGAIN`, 1 for any other answer (a read that blocks never exits).
fn nb_read() -> ! {
    let mut p = [0u32; 2];
    if sys::pipe_typed(&mut p, sys::PIPE_NONBLOCK) != 0 {
        sys::exit(2);
    }
    let mut b = [0u8; 1];
    let rc = sys::read(p[0] as u64, &mut b);
    sys::exit(if rc == -11 { 0 } else { 1 })
}

/// Start a `nap` child and reap it: the process `/proc/tasks` shows one
/// child of.
fn tree() -> ! {
    let gc = spawn_child(&[b"nap", b"1500"]);
    if gc > 0 {
        let _ = reap_by_tid(gc);
    }
    sys::exit(if gc > 0 { 0 } else { 1 })
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
    let f = sys::open(sys::cstr!(b"/fat/CONFIG.INI"), 0);
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

/// The grandchild of an orphan test. It waits (clock deadline) until
/// `/proc/tasks` shows its parent as `want`, then stays alive until the
/// adopter has listed it (the adopter registers the service name `name`: no
/// deadline stands in for "listed", the ceiling only ends a stuck adopter),
/// and exits [`ORPHAN_ADOPTED`]; [`ORPHAN_NOT_ADOPTED`] at the deadline.
fn orphan_leaf(want: u32, name: &[u8]) -> ! {
    let me = sys::getpid() as u32;
    let mut deadline = Deadline::in_ms(5_000);
    while !deadline.expired() {
        if proc_parent_of(me) == want {
            let mut buf = [0u8; 48];
            if name.len() < buf.len() {
                buf[..name.len()].copy_from_slice(name);
                let mut released = Deadline::in_ms(30_000);
                while sys::service_discover(&buf[..name.len() + 1]) <= 0 && !released.expired() {
                    sys::sleep(2);
                }
            }
            sys::exit(ORPHAN_ADOPTED);
        }
        sys::sleep(5);
    }
    sys::exit(ORPHAN_NOT_ADOPTED)
}

/// A subreaper: marks itself, starts a child that starts the orphan and
/// exits, and checks that the orphan came to it and not to init. Exits with a
/// bit per failed step (0: all held).
fn subreaper(name: &[u8]) -> ! {
    let sme = sys::getpid() as u32;
    let mut bad = 0i32;
    if sys::task_subreaper(sys::SUBREAPER_SET) != 1 { bad |= 1; }
    let mut sme_dec = [0u8; 20];
    let want = dec(sme as u64, &mut sme_dec);
    let mid = spawn_child(&[b"orphan-mid", want, name]);
    if mid <= 0 { sys::exit(bad | 2); }
    let (got, st) = reap_by_tid(mid);
    if got != mid || st != 0 { bad |= 4; }
    let orphan = only_child_of(sme);
    // Release the orphan: it has been listed. The name goes with this task.
    let mut buf = [0u8; 48];
    if name.len() < buf.len() {
        buf[..name.len()].copy_from_slice(name);
        let _ = sys::service_register(&buf[..name.len() + 1], 0, 0);
    }
    if orphan == 0 { bad |= 8; }
    if orphan != 0 {
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
// register lost by the reflect or by the resume shows. The process exits 0
// when the whole conversation held, else with the number of the step that did
// not.

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
        }
        (1, FOREIGN_CALL_B) => {
            // The answer to the first trap, and the kept register, came back.
            if f.gpr[FOREIGN_COPY_REG] != FOREIGN_ARG * 2 + 1 || f.gpr[FOREIGN_KEEP_REG] != FOREIGN_KEEP {
                sys::exit(12);
            }
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

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Process entry and what a process knows about itself.
//!
//! The kernel starts an image at its ELF entry, [`_azos_entry`], with the
//! startup block of `SYS_SPAWN_EX` (arguments, environment, working
//! directory, fds 0..7 as handles) addressed by the second argument register
//! (`a1`, `x1`, `rsi`), or 0 when the spawner gave none. The entry runs
//! [`azos_start`]: it reads the block, calls the C `main` that `rustc`
//! generates for a Rust `fn main` (which goes through `std`'s `lang_start`),
//! and exits with its status.

use core::cell::UnsafeCell;

use crate::pure::{cstr_at, env_lookup, FdEntry, FdTable};
use crate::sys::{self, syscall6};
use azos_abi::syscall_nr::{CAP_INFO_LOOKUP, SYS_CAP_INFO, SYS_EXIT, SYS_GETPID};
use azos_abi::ushell::{StartupBlock, STARTUP_BLOCK_SIZE};

// The kernel starts an x86_64 image with rsp 16-byte aligned, and a function
// expects rsp + 8 aligned (a `call` pushed its return address): realign and
// call. The other ISAs enter the Rust function directly, with the kernel's
// first two argument registers intact.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl _azos_entry",
    ".type _azos_entry, @function",
    "_azos_entry:",
    "    xor ebp, ebp",
    "    and rsp, -16",
    "    call {start}",
    "    ud2",
    ".size _azos_entry, . - _azos_entry",
    start = sym azos_start,
);
#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".globl _azos_entry",
    ".type _azos_entry, @function",
    "_azos_entry:",
    "    j {start}",
    ".size _azos_entry, . - _azos_entry",
    start = sym azos_start,
);
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".globl _azos_entry",
    ".type _azos_entry, %function",
    "_azos_entry:",
    "    b {start}",
    ".size _azos_entry, . - _azos_entry",
    start = sym azos_start,
);

/// The ELF note that names the ABI version this program was built against;
/// the loader refuses an image whose note names another one.
#[repr(C, align(4))]
struct AbiNote {
    namesz: u32,
    descsz: u32,
    ty: u32,
    name: [u8; 8],
    desc: u32,
}

#[used]
#[link_section = ".note.azos.abi"]
static ABI_NOTE: AbiNote = AbiNote {
    namesz: 5,
    descsz: 4,
    ty: azos_abi::ABI_NOTE_TYPE,
    name: *b"AZOS\0\0\0\0",
    desc: azos_abi::ABI_VERSION,
};

struct State {
    fds: FdTable,
    block: Option<StartupBlock>,
}

struct Cell(UnsafeCell<State>);
// SAFETY: written once by `azos_start`, before `main` and so before any
// thread exists; read-only afterwards.
unsafe impl Sync for Cell {}

static STATE: Cell = Cell(UnsafeCell::new(State { fds: FdTable::new(), block: None }));

fn state() -> &'static State {
    // SAFETY: see `Cell`.
    unsafe { &*STATE.0.get() }
}

unsafe extern "C" {
    /// The `main` `rustc` generates for a Rust `fn main` (`std::rt::lang_start`).
    fn main(argc: isize, argv: *const *const u8) -> i32;
}

/// The Rust half of the entry. Never returns.
extern "C" fn azos_start(_a0: usize, a1: usize) -> ! {
    // Keep the note in the object the entry lives in (an archive member that
    // nothing referenced would not be linked, and its note with it).
    core::hint::black_box(&ABI_NOTE);
    init(a1);
    // SAFETY: `main` is the program's, called once, with no argv (the
    // arguments come from the startup block, not from the stack).
    let code = unsafe { main(0, core::ptr::null()) };
    exit(code)
}

/// Read the startup block at `a1`; 0, or a block that does not validate,
/// leaves the defaults (no arguments; fds 1 and 2 the console).
fn init(a1: usize) {
    if a1 == 0 || a1 % 8 != 0 {
        return;
    }
    // SAFETY: the kernel wrote the block at `a1` on this process's own stack,
    // above the stack pointer it started with; nothing has written there.
    let raw = unsafe { core::slice::from_raw_parts(a1 as *const u8, STARTUP_BLOCK_SIZE) };
    let Some(sb) = StartupBlock::from_bytes(raw).filter(|b| b.validate()) else { return };
    // SAFETY: before `main`; see `Cell`.
    let st = unsafe { &mut *STATE.0.get() };
    st.fds = FdTable::fd_table_from_startup(&sb.fds);
    st.block = Some(sb);
}

/// End the whole process with `code` (`SYS_EXIT`).
pub fn exit(code: i32) -> ! {
    // SAFETY: a plain call.
    unsafe { syscall6(SYS_EXIT, code as u64, 0, 0, 0, 0, 0) };
    sys::trap()
}

/// The process id (a thread's is its group leader's task id).
pub fn getpid() -> u32 {
    // SAFETY: a plain call.
    unsafe { syscall6(SYS_GETPID, 0, 0, 0, 0, 0, 0) as u32 }
}

fn blob(ptr: u64, len: u32) -> &'static [u8] {
    if ptr == 0 || len == 0 {
        return &[];
    }
    // SAFETY: the pointer and the length come from a validated startup block
    // the kernel laid out on this process's stack, above its stack pointer.
    unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) }
}

/// Number of arguments (0 without a startup block).
pub fn argc() -> usize {
    state().block.map_or(0, |b| b.argc as usize)
}

/// Argument `i` (`arg(0)` is the name the program was run by).
pub fn arg(i: usize) -> Option<&'static [u8]> {
    let b = state().block?;
    cstr_at(blob(b.argv, b.argv_bytes), i)
}

/// The environment strings, `KEY=VALUE`, NUL separated (empty without a block).
pub fn env_blob() -> &'static [u8] {
    state().block.map_or(&[], |b| blob(b.env, b.env_bytes))
}

/// Environment string `i` (`KEY=VALUE`).
pub fn env_at(i: usize) -> Option<&'static [u8]> {
    cstr_at(env_blob(), i)
}

/// The value of environment variable `key` as the spawner gave it.
pub fn getenv(key: &[u8]) -> Option<&'static [u8]> {
    env_lookup(env_blob(), key)
}

/// The working directory the spawner gave, `/` if none. The kernel keeps no
/// working directory: a program makes its paths absolute against this.
pub fn cwd() -> &'static [u8] {
    match state().block {
        Some(b) if b.cwd != 0 => blob(b.cwd, b.cwd_bytes),
        _ => b"/",
    }
}

/// What small fd `fd` (0..8) is.
pub fn fd(fd: u64) -> FdEntry {
    state().fds.fd_slot(fd)
}

/// This task's handle of kind `kind` (`azos_abi::cap::ty`), resource index
/// `resource`; `<= 0` when it holds none.
pub fn cap_lookup(kind: u8, resource: u32) -> isize {
    // SAFETY: a plain call.
    unsafe { syscall6(SYS_CAP_INFO, 0, CAP_INFO_LOOKUP, kind as u64, resource as u64, 0, 0) }
}

/// This task's endpoint capability to the kernel-hosted interface `key`
/// (`azos_devif::key`) that carries `badge`; `<= 0` when its row grants none.
pub fn cap_lookup_host(key: u16, badge: u32) -> isize {
    // SAFETY: a plain call.
    unsafe {
        syscall6(
            SYS_CAP_INFO,
            0,
            CAP_INFO_LOOKUP,
            azos_abi::cap::ty::ENDPOINT.raw() as u64,
            (key as u64) << 32 | badge as u64,
            0,
            0,
        )
    }
}

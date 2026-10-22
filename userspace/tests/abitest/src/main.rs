// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Syscall ABI conformance test for a ring-3 process.
//!
//! WHY THIS EXISTS
//!
//! On 2026-08-21 an audit found `crates/core/libsys` and the kernel handlers
//! disagreeing on the argument shape of a dozen syscalls. `exec` declared
//! `(entry_addr, stack_addr)` where the kernel read `(elf_ptr, elf_len)`.
//! `drv_mmap` passed `(phys, size)` where the dispatcher indexes
//! `(drv_id, mmio_idx)`. The raw disk calls passed `(sector, buf, len)` where the
//! kernel read `(sector, count, buf)` (they are the `block` endpoint now). `pipe` handed the kernel a
//! `[u64; 2]` for an `int[2]`.
//!
//! Not one of those was caught by a test, a build, or a boot — because
//! **no userspace program called any of them.** They compiled, they were
//! documented, and they had never once been executed. That is the recurring
//! shape in this tree, and a wrapper nothing calls is a wrapper nothing
//! checks.
//!
//! This binary is the check. It calls the wrappers whose contract was
//! verified against `crates/core/syscall/src/dispatch.rs` and
//! `crates/core/syscall/src/handlers.rs`, and asserts the kernel returns what the
//! libsys doc comment promises. If either side drifts again, this fails on
//! the next `qemu-abitest` run instead of in three months on hardware.
//!
//! WHAT IT WILL NOT DO
//!
//!   * No destructive or one-way call. The filter op is irreversible and would
//!     break every later assertion; `shutdown`/`reboot` end the run;
//!     `unlink` mutates the FAT32 image the other scenarios
//!     grep; `kill` targets a live task. None are called (a stop REQUEST to
//!     the test's own orphan child, which only ends its wait, is the one
//!     exception).
//!   * No dependence on a disk or a NIC. `make qemu-smp` carries neither,
//!     so every assertion here holds with or without them.
//!
//! WHAT A FAILURE MEANS
//!
//! Each line prints the raw `rc`. Two different "denied" codes exist in this
//! kernel — `-99` from a handler-side `cap_check`, `-1` from a dispatch-side
//! one — so assertions test for *negativity* and print the code rather than
//! pinning a value that is not uniform. Pinning it would make the test
//! brittle; printing it makes the split visible.

#![no_std]
#![no_main]

// The raw syscalls, the fault and FP probes below select their instructions
// per ISA; on an ISA with no branch the build stops here instead of losing
// a check.
#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("abitest: no syscall instruction for this ISA (riscv64, aarch64, x86_64)");

use azos_libsys as sys;
use sys::dev::{MotorCall, MotorClient, Regs};

// The wait bounded by the guest's clock, the `/proc/tasks` view and the child
// spawner, shared with the image the children run (`abichild`).
// Each program uses the half of it the other does not.
#[allow(dead_code)]
#[path = "../../abichild/src/shared.rs"]
mod shared;
use shared::{
    children_of, dec, proc_task_rows, reap_by_tid, spawn_child, Deadline,
};

static mut FAILURES: u32 = 0;
static mut CHECKS: u32 = 0;

fn report(name: &[u8], ok: bool, rc: isize) {
    out(if ok { b"[ABITEST]   ok   " } else { b"[ABITEST]  FAIL  " });
    out(name);
    out(b" rc=");
    print_i(rc);
    out(b"\n");
    // `overflow-checks = true` and `panic = "abort"`: a wrapping increment
    // here would reset the board. Saturating cannot.
    unsafe {
        CHECKS = CHECKS.saturating_add(1);
        if !ok {
            FAILURES = FAILURES.saturating_add(1);
        }
    }
}

/// Minimal signed-decimal print — no `core::fmt` in a no_std ring-3 binary.
/// Same shape as `userspace/tests/captest`, including the `i64` widening that
/// keeps `isize::MIN` from overflowing on negation.
fn print_i(v: isize) {
    if v < 0 {
        out(b"-");
    }
    let mut n = if v < 0 { (v as i64).unsigned_abs() } else { v as u64 };
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    }
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    out(&buf[i..]);
}

/// The kernel must reject this call.
fn expect_err(name: &[u8], rc: isize) {
    report(name, rc < 0, rc);
}

/// The console line being built, written in ONE `write` when it ends.
///
/// A check line used to go out as five writes (prefix, name, " rc=", the
/// number, the newline). The console keeps a ring-3 line whole only within a
/// single `write`, so under load another task's output landed between the
/// pieces and split the very marker a gate row waits for (`map granted 256 of
/// 256 pages`, 3 of 72 boots in W9-KPF's runs). Every print in this program goes
/// through `out`; the bytes reach the console when the line is complete.
struct LineBuf {
    buf: [u8; 256],
    len: usize,
}

static mut LINE: LineBuf = LineBuf { buf: [0; 256], len: 0 };

fn out(s: &[u8]) {
    // Single-threaded: the threads some checks start print nothing.
    let line = unsafe { &mut *core::ptr::addr_of_mut!(LINE) };
    for &b in s {
        if line.len == line.buf.len() {
            sys::print(&line.buf[..line.len]);
            line.len = 0;
        }
        line.buf[line.len] = b;
        line.len += 1;
        if b == b'\n' {
            sys::print(&line.buf[..line.len]);
            line.len = 0;
        }
    }
}

fn outln(s: &[u8]) {
    out(s);
    out(b"\n");
}

/// The kernel must return exactly `want`.
fn expect_eq(name: &[u8], rc: isize, want: isize) {
    report(name, rc == want, rc);
}

/// The kernel must return something strictly positive.
fn expect_pos(name: &[u8], rc: isize) {
    report(name, rc > 0, rc);
}

/// A plain boolean assertion with no syscall return to show.
fn expect_true(name: &[u8], ok: bool) {
    report(name, ok, if ok { 0 } else { -1 });
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    abitest_main()
}

fn abitest_main() -> ! {
    outln(b"[ABITEST] Starting - libsys/kernel ABI conformance");

    check_process();
    // Chain E commit 8: the native syscall register contract. Early, before
    // any check leaves a child behind.
    check_syscall_register_contract();
    check_console_io();
    check_paths_and_nul();
    check_vdso();
    check_hwcap();
    check_uptime_without_a_trap();
    check_sleep_blocks();
    check_kernel_stubs();
    check_missing_dispatch_arms();
    check_inline_dispatch_arms_refuse();
    check_udp_loopback();
    check_wait_reaps_child();
    check_wait_status_reports_the_exit_code();
    check_waitpid_targets_one_child();
    check_fault_kills_only_the_child();
    check_exit_gives_memory_back();
    check_exit_storm();
    check_unreaped_children_are_kept();
    check_proc_view();
    // The memory permissions a process starts with; each starts a child that
    // breaks one and reaps it by TID.
    check_code_is_read_only();
    check_rodata_not_executable();
    check_mmap_prot();
    // Wave 13 (THREADS): native threads. They reap their own children.
    check_thread_storm();
    check_threads();
    // Wave 15 (plan 4a): after the thread checks (their rows stop reading
    // at the last of them), and reaping only their own children by TID.
    check_thread_objects();
    check_orphans();
    // D6: the foreign-ABI family (trap reflect and resume), a child process.
    check_foreign_abi();
    // aarch64 lazy FP. After the wait()/waitpid() checks: threads, no children.
    #[cfg(target_arch = "aarch64")]
    check_neon_state_is_per_task();
    // x86_64: the same property for XMM0-XMM15 and MXCSR (the images are
    // hard-float; the kernel saves the state on a switch,
    // kernel/src/entry/x86_64/fp.rs).
    // arch-only: x86_64's FP probe (XMM/MXCSR); aarch64 has its NEON twin, riscv64 images use no FP registers.
    #[cfg(target_arch = "x86_64")]
    check_sse_state_is_per_task();
    check_udp_client_server();
    // After every check that reaps with `wait()`: the spawned child is reaped
    // by TID, and a notice left behind by a failure here must not be taken by
    // one of those.
    check_endpoint_cap();
    check_entropy_read();
    check_spawn();
    // The four user-shell calls' refusals. Right after
    // `check_spawn`, while this task has no live child: 611's ancestor check
    // must find nothing below it.
    check_user_shell_calls_refuse();
    // AFTER `check_spawn`, because it spawns and
    // reaps a server of its own and `check_spawn` asserts `waitpid` targets
    // one child: a second live child during those assertions would be a
    // second thing `wait()` could reap.
    check_endpoint_exchange();
    // LAST, and it must stay last: this one LATCHES the machine's e-stop, so
    // every motor write for the rest of the boot is clamped to zero. Any check
    // placed after it would be running on a robot that has been shut down.
    check_estop_is_a_real_safety_path();
    // AFTER the e-stop on purpose, and last of all: this one ALLOCATES, and a
    // check that runs after it would run under whatever memory pressure it
    // leaves. It asserts nothing itself — it reports, and the gate row for the
    // `mem-quota-canary` build reads the number.
    report_map_growth();

    let failed = unsafe { FAILURES };
    let total = unsafe { CHECKS };
    out(b"[ABITEST] ");
    print_i(total as isize);
    outln(b" check(s) run");
    if failed == 0 {
        outln(b"[ABITEST] ALL PASSED");
        sys::exit(0);
    } else {
        out(b"[ABITEST] FAILED: ");
        print_i(failed as isize);
        outln(b" check(s)");
        sys::exit(1);
    }
}

// ── Lazy FP (aarch64): every task keeps its own V0-V31/FPCR ─────────────
//
// The aarch64 kernel no longer saves the FP/SIMD registers on every trap:
// a task's first FP instruction after a switch-in traps (CPACR_EL1.FPEN)
// and loads that task's state, and the state is saved on switch-out only
// if the task used FP since it came in (kernel/src/entry/aarch64/
// fp_lazy.rs). These two checks are what fails if any of that is wrong.
//
// The yield number restated from crates/core/abi/src/syscall_nr.rs (libsys
// imports it privately); the kernel's aarch64 dispatcher reads x8.
// arch-only: the syscall number the FP probes (aarch64, x86_64) issue raw.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const NEON_SYS_YIELD: u64 = 11;

/// Fill V0-V31 with `p + n` in both lanes and FPCR with `fpcr`, make one
/// syscall (`nr`, with `a0` and `a1`: a yield), then read everything back. One asm block,
/// so nothing but the kernel can touch the registers in between. Returns
/// (syscall x0, OR of every lane's difference from its expected value, 0
/// when FPCR also read back unchanged).
#[cfg(target_arch = "aarch64")]
fn neon_fill_syscall_check(p: u64, fpcr: u64, nr: u64, a0: u64, a1: u64) -> (isize, u64) {
    let rc: isize;
    let mut acc: u64 = 0;
    unsafe {
        core::arch::asm!(
            "msr FPCR, {fpcr}",
            "add x10, {p}, #0", "dup v0.2d, x10",
            "add x10, {p}, #1", "dup v1.2d, x10",
            "add x10, {p}, #2", "dup v2.2d, x10",
            "add x10, {p}, #3", "dup v3.2d, x10",
            "add x10, {p}, #4", "dup v4.2d, x10",
            "add x10, {p}, #5", "dup v5.2d, x10",
            "add x10, {p}, #6", "dup v6.2d, x10",
            "add x10, {p}, #7", "dup v7.2d, x10",
            "add x10, {p}, #8", "dup v8.2d, x10",
            "add x10, {p}, #9", "dup v9.2d, x10",
            "add x10, {p}, #10", "dup v10.2d, x10",
            "add x10, {p}, #11", "dup v11.2d, x10",
            "add x10, {p}, #12", "dup v12.2d, x10",
            "add x10, {p}, #13", "dup v13.2d, x10",
            "add x10, {p}, #14", "dup v14.2d, x10",
            "add x10, {p}, #15", "dup v15.2d, x10",
            "add x10, {p}, #16", "dup v16.2d, x10",
            "add x10, {p}, #17", "dup v17.2d, x10",
            "add x10, {p}, #18", "dup v18.2d, x10",
            "add x10, {p}, #19", "dup v19.2d, x10",
            "add x10, {p}, #20", "dup v20.2d, x10",
            "add x10, {p}, #21", "dup v21.2d, x10",
            "add x10, {p}, #22", "dup v22.2d, x10",
            "add x10, {p}, #23", "dup v23.2d, x10",
            "add x10, {p}, #24", "dup v24.2d, x10",
            "add x10, {p}, #25", "dup v25.2d, x10",
            "add x10, {p}, #26", "dup v26.2d, x10",
            "add x10, {p}, #27", "dup v27.2d, x10",
            "add x10, {p}, #28", "dup v28.2d, x10",
            "add x10, {p}, #29", "dup v29.2d, x10",
            "add x10, {p}, #30", "dup v30.2d, x10",
            "add x10, {p}, #31", "dup v31.2d, x10",
            "svc #0",
            "mrs x12, FPCR",
            "eor x12, x12, {fpcr}",
            "orr {acc}, {acc}, x12",
            "add x12, {p}, #0", "mov x10, v0.d[0]", "mov x11, v0.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #1", "mov x10, v1.d[0]", "mov x11, v1.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #2", "mov x10, v2.d[0]", "mov x11, v2.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #3", "mov x10, v3.d[0]", "mov x11, v3.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #4", "mov x10, v4.d[0]", "mov x11, v4.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #5", "mov x10, v5.d[0]", "mov x11, v5.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #6", "mov x10, v6.d[0]", "mov x11, v6.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #7", "mov x10, v7.d[0]", "mov x11, v7.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #8", "mov x10, v8.d[0]", "mov x11, v8.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #9", "mov x10, v9.d[0]", "mov x11, v9.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #10", "mov x10, v10.d[0]", "mov x11, v10.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #11", "mov x10, v11.d[0]", "mov x11, v11.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #12", "mov x10, v12.d[0]", "mov x11, v12.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #13", "mov x10, v13.d[0]", "mov x11, v13.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #14", "mov x10, v14.d[0]", "mov x11, v14.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #15", "mov x10, v15.d[0]", "mov x11, v15.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #16", "mov x10, v16.d[0]", "mov x11, v16.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #17", "mov x10, v17.d[0]", "mov x11, v17.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #18", "mov x10, v18.d[0]", "mov x11, v18.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #19", "mov x10, v19.d[0]", "mov x11, v19.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #20", "mov x10, v20.d[0]", "mov x11, v20.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #21", "mov x10, v21.d[0]", "mov x11, v21.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #22", "mov x10, v22.d[0]", "mov x11, v22.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #23", "mov x10, v23.d[0]", "mov x11, v23.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #24", "mov x10, v24.d[0]", "mov x11, v24.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #25", "mov x10, v25.d[0]", "mov x11, v25.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #26", "mov x10, v26.d[0]", "mov x11, v26.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #27", "mov x10, v27.d[0]", "mov x11, v27.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #28", "mov x10, v28.d[0]", "mov x11, v28.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #29", "mov x10, v29.d[0]", "mov x11, v29.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #30", "mov x10, v30.d[0]", "mov x11, v30.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "add x12, {p}, #31", "mov x10, v31.d[0]", "mov x11, v31.d[1]",
            "eor x10, x10, x12", "eor x11, x11, x12", "orr {acc}, {acc}, x10", "orr {acc}, {acc}, x11",
            "msr FPCR, xzr",
            p = inout(reg) p => _,
            fpcr = inout(reg) fpcr => _,
            acc = inout(reg) acc,
            inout("x0") a0 as isize => rc,
            in("x1") a1,
            in("x8") nr,
            out("x10") _, out("x11") _, out("x12") _,
            out("v0") _,
            out("v1") _,
            out("v2") _,
            out("v3") _,
            out("v4") _,
            out("v5") _,
            out("v6") _,
            out("v7") _,
            out("v8") _,
            out("v9") _,
            out("v10") _,
            out("v11") _,
            out("v12") _,
            out("v13") _,
            out("v14") _,
            out("v15") _,
            out("v16") _,
            out("v17") _,
            out("v18") _,
            out("v19") _,
            out("v20") _,
            out("v21") _,
            out("v22") _,
            out("v23") _,
            out("v24") _,
            out("v25") _,
            out("v26") _,
            out("v27") _,
            out("v28") _,
            out("v29") _,
            out("v30") _,
            out("v31") _,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x13") _,
            lateout("x14") _, lateout("x15") _, lateout("x16") _, lateout("x17") _,
            lateout("x30") _,
            options(nostack),
        );
    }
    (rc, acc)
}

/// One task's share of `check_neon_state_is_per_task`: `rounds` yields, each
/// with a fresh pattern derived from `seed`. Returns the number of rounds in
/// which any V register (or FPCR) came back changed.
#[cfg(target_arch = "aarch64")]
fn neon_task_rounds(seed: u64, fpcr: u64, rounds: u64) -> u64 {
    let mut bad = 0;
    for r in 0..rounds {
        let (_, acc) = neon_fill_syscall_check(seed ^ (r << 8), fpcr, NEON_SYS_YIELD, 0, 0);
        if acc != 0 {
            bad += 1;
        }
    }
    bad
}

/// The threads of [`check_neon_state_is_per_task`]: the rounds in which each
/// saw a register change, `u64::MAX` until it finished.
#[cfg(target_arch = "aarch64")]
static NEON_BAD: [AtomicU64; 3] = [const { AtomicU64::new(u64::MAX) }; 3];

/// One thread of [`check_neon_state_is_per_task`]: thread `k` fills its own
/// pattern and an FPCR rounding mode of its own.
#[cfg(target_arch = "aarch64")]
extern "C" fn neon_thread(_z: u64, _stack: u64, k: u64) -> ! {
    let seed = 0x5EED_0000_0000_0000 | ((k + 1) << 40);
    NEON_BAD[k as usize].store(neon_task_rounds(seed, (k + 1) << 22, 300), AO::Release);
    sys::thread_exit(0)
}

/// Four tasks (this one + three threads) each fill V0-V31/FPCR with their own
/// values and yield, 300 times, checking every register after every yield.
/// With lazy FP a task's values survive only if the kernel saves them when
/// another FP-using task takes the registers and loads them back on its next
/// first use; a skipped save or restore makes some task read another's
/// values. On `-smp 1` all four share one hart, so they necessarily take the
/// registers from each other.
#[cfg(target_arch = "aarch64")]
fn check_neon_state_is_per_task() {
    const ROUNDS: u64 = 300;
    const THREADS: usize = 3;
    // FPCR RMode (bits 23:22) differs per task, so FPCR is per-task too.
    let mut made = 0;
    for k in 0..THREADS {
        NEON_BAD[k].store(u64::MAX, AO::Release);
        T_CTID[k].store(u32::MAX, AO::Release);
        if sys::thread_create(neon_thread, t_stack_top(k), k as u64, T_CTID[k].as_ptr()) > 0 {
            made += 1;
        }
    }
    expect_eq(b"neon: start three FP-using threads", made, THREADS as isize);
    let own_bad = neon_task_rounds(0x5EED_0000_0000_0000, 0, ROUNDS);
    let mut thread_bad: isize = 0;
    let mut joined = 0;
    for k in 0..THREADS {
        if t_join(k) {
            joined += 1;
            let bad = NEON_BAD[k].load(AO::Acquire);
            thread_bad += if bad == u64::MAX { 1 } else { bad as isize };
        }
    }
    expect_eq(b"neon: all three threads joined", joined, THREADS as isize);
    expect_eq(b"neon: parent's V0-V31/FPCR survived 300 yields", own_bad as isize, 0);
    expect_eq(b"neon: threads' V0-V31/FPCR survived 300 yields each", thread_bad, 0);
}

// ── FP state (x86_64): every task keeps its own XMM0-XMM15/MXCSR ────────

/// Load XMM0-XMM15 with `p + n` in both quadwords and MXCSR with the
/// default plus `rc` (rounding control, bits 14:13), make one syscall (`nr`,
/// with `a0` and `a1`: a yield), then store everything back. One asm block, so nothing
/// but the kernel can touch the registers in between. Returns (rax, OR of
/// every quadword's difference from its expected value, and MXCSR's).
// arch-only: x86_64's FP probe (XMM/MXCSR); aarch64 has its NEON twin, riscv64 images use no FP registers.
#[cfg(target_arch = "x86_64")]
fn sse_fill_syscall_check(p: u64, rc: u32, nr: u64, a0: u64, a1: u64) -> (isize, u64) {
    const MXCSR_DEFAULT: u32 = 0x1F80;
    let input: [u64; 32] = core::array::from_fn(|k| p + (k / 2) as u64);
    let mut output = [0u64; 32];
    let mx_in: u32 = MXCSR_DEFAULT | rc;
    let mut mx_out: u32 = 0;
    let rv: isize;
    unsafe {
        core::arch::asm!(
            "ldmxcsr [{mxi}]",
            "movdqu xmm0, [{i} + 0]",
            "movdqu xmm1, [{i} + 16]",
            "movdqu xmm2, [{i} + 32]",
            "movdqu xmm3, [{i} + 48]",
            "movdqu xmm4, [{i} + 64]",
            "movdqu xmm5, [{i} + 80]",
            "movdqu xmm6, [{i} + 96]",
            "movdqu xmm7, [{i} + 112]",
            "movdqu xmm8, [{i} + 128]",
            "movdqu xmm9, [{i} + 144]",
            "movdqu xmm10, [{i} + 160]",
            "movdqu xmm11, [{i} + 176]",
            "movdqu xmm12, [{i} + 192]",
            "movdqu xmm13, [{i} + 208]",
            "movdqu xmm14, [{i} + 224]",
            "movdqu xmm15, [{i} + 240]",
            "syscall",
            "movdqu [{o} + 0], xmm0",
            "movdqu [{o} + 16], xmm1",
            "movdqu [{o} + 32], xmm2",
            "movdqu [{o} + 48], xmm3",
            "movdqu [{o} + 64], xmm4",
            "movdqu [{o} + 80], xmm5",
            "movdqu [{o} + 96], xmm6",
            "movdqu [{o} + 112], xmm7",
            "movdqu [{o} + 128], xmm8",
            "movdqu [{o} + 144], xmm9",
            "movdqu [{o} + 160], xmm10",
            "movdqu [{o} + 176], xmm11",
            "movdqu [{o} + 192], xmm12",
            "movdqu [{o} + 208], xmm13",
            "movdqu [{o} + 224], xmm14",
            "movdqu [{o} + 240], xmm15",
            "stmxcsr [{mxo}]",
            "ldmxcsr [{mxd}]",
            i = in(reg) input.as_ptr(),
            o = in(reg) output.as_mut_ptr(),
            mxi = in(reg) &mx_in,
            mxo = in(reg) &mut mx_out,
            mxd = in(reg) &MXCSR_DEFAULT,
            inlateout("rax") nr as isize => rv,
            in("rdi") a0,
            in("rsi") a1,
            // Not late: `syscall` writes them, and the pointers above are
            // read after it.
            out("rcx") _,
            out("r11") _,
            out("xmm0") _,
            out("xmm1") _,
            out("xmm2") _,
            out("xmm3") _,
            out("xmm4") _,
            out("xmm5") _,
            out("xmm6") _,
            out("xmm7") _,
            out("xmm8") _,
            out("xmm9") _,
            out("xmm10") _,
            out("xmm11") _,
            out("xmm12") _,
            out("xmm13") _,
            out("xmm14") _,
            out("xmm15") _,
            options(nostack),
        );
    }
    let mut acc = (mx_out ^ mx_in) as u64;
    for k in 0..32 {
        acc |= output[k] ^ input[k];
    }
    (rv, acc)
}

/// `rounds` yields, each after loading XMM0-XMM15/MXCSR with a fresh
/// pattern derived from `seed`; the rounds in which anything came back
/// changed.
// arch-only: x86_64's FP probe (XMM/MXCSR); aarch64 has its NEON twin, riscv64 images use no FP registers.
#[cfg(target_arch = "x86_64")]
fn sse_task_rounds(seed: u64, rc: u32, rounds: u64) -> u64 {
    (0..rounds).filter(|r| sse_fill_syscall_check(seed ^ (r << 8), rc, NEON_SYS_YIELD, 0, 0).1 != 0).count() as u64
}

/// The threads of [`check_sse_state_is_per_task`]: the rounds in which each
/// saw a register change, `u64::MAX` until it finished.
// arch-only: x86_64's FP probe (XMM/MXCSR); aarch64 has its NEON twin, riscv64 images use no FP registers.
#[cfg(target_arch = "x86_64")]
static SSE_BAD: [AtomicU64; 3] = [const { AtomicU64::new(u64::MAX) }; 3];

/// One thread of [`check_sse_state_is_per_task`]: thread `k` loads its own
/// pattern and an MXCSR rounding mode of its own.
// arch-only: x86_64's FP probe (XMM/MXCSR); aarch64 has its NEON twin, riscv64 images use no FP registers.
#[cfg(target_arch = "x86_64")]
extern "C" fn sse_thread(_z: u64, _stack: u64, k: u64) -> ! {
    let seed = 0x5EED_0000_0000_0000 | ((k + 1) << 40);
    SSE_BAD[k as usize].store(sse_task_rounds(seed, ((k + 1) as u32) << 13, 300), AO::Release);
    sys::thread_exit(0)
}

/// Four tasks (this one and three threads) each load their own XMM0-XMM15
/// and MXCSR rounding mode and yield 300 times, checking every register
/// after every yield: a save or restore the switch skipped shows up as
/// another task's values.
// arch-only: x86_64's FP probe (XMM/MXCSR); aarch64 has its NEON twin, riscv64 images use no FP registers.
#[cfg(target_arch = "x86_64")]
fn check_sse_state_is_per_task() {
    const ROUNDS: u64 = 300;
    const THREADS: usize = 3;
    let mut made = 0;
    for k in 0..THREADS {
        SSE_BAD[k].store(u64::MAX, AO::Release);
        T_CTID[k].store(u32::MAX, AO::Release);
        if sys::thread_create(sse_thread, t_stack_top(k), k as u64, T_CTID[k].as_ptr()) > 0 {
            made += 1;
        }
    }
    expect_eq(b"sse: start three FP-using threads", made, THREADS as isize);
    let own_bad = sse_task_rounds(0x5EED_0000_0000_0000, 0, ROUNDS);
    let mut thread_bad: isize = 0;
    let mut joined = 0;
    for k in 0..THREADS {
        if t_join(k) {
            joined += 1;
            let bad = SSE_BAD[k].load(AO::Acquire);
            thread_bad += if bad == u64::MAX { 1 } else { bad as isize };
        }
    }
    expect_eq(b"sse: all three threads joined", joined, THREADS as isize);
    expect_eq(b"sse: parent's XMM0-XMM15/MXCSR survived 300 yields", own_bad as isize, 0);
    expect_eq(b"sse: threads' XMM0-XMM15/MXCSR survived 300 yields each", thread_bad, 0);
}

/// Map far more than any budget allows, and report what was granted.
///
/// **Owner decision 102 put a frame budget on every task; nothing in the gate
/// had ever seen it REFUSE.** A quota that never refuses anything is
/// indistinguishable from one that is not wired, and every other assertion in
/// this program passes either way.
///
/// One granule at a time (`SYS_MO_MAP`, anonymous), so the honest observable is
/// the *granted* total: under `mem-quota-canary` the autorun budget is 64
/// pages, so a request for 1 MiB (256 pages) must run dry far short of it. On a
/// normal build the budget is 2048 and the same request is satisfied in full
/// — which is why this reports instead of asserting: one program, two correct
/// outcomes, and the gate row knows which build it booted.
///
/// The request is deliberately well under the user ceiling (32 MiB) so the VA
/// cannot be what bounds it; only the budget or an empty allocator can, and the
/// kernel's own `mem quota refused` counter tells those two apart.
fn report_map_growth() {
    const ASK_BYTES: usize = 1024 * 1024;
    let pages = ASK_BYTES / sys::PAGE_SIZE;
    let mut granted = 0usize;
    while granted < pages
        && sys::mmap(0, sys::PAGE_SIZE as u64, sys::PROT_READ | sys::PROT_WRITE, 0, sys::MAP_ANON_FD, 0) > 0
    {
        granted += 1;
    }
    out(b"[ABITEST] map granted ");
    print_i(granted as isize);
    out(b" of ");
    print_i(pages as isize);
    outln(b" pages requested");
}

/// Call `endpoint.demo` and check the ANSWER.
///
/// # What this proves that a return code cannot
///
/// From ring 3 an authority refusal and a failed exchange are both `-1`, so
/// "the call did not fail" says almost nothing. What separates them is the
/// payload: `epsrv` answers `w0 + 1`, so a reply that carries the successor of
/// the word THIS call sent cannot have come from zeroed registers, from a
/// stale slot, or from a different exchange. That is the property stage 2b is
/// for — a capability-addressed call reaching a server that was never named by
/// TID.
///
/// # Why it spawns its own server instead of reusing the `uhello` child
///
/// A ring-3 program's role on an endpoint is its capability permission, and
/// permissions come from the topology row looked up by IMAGE name — so the
/// server has to be its own image. `EPSRV.ELF` holds `READ` on
/// `endpoint.demo`; this program holds `WRITE`. See
/// `userspace/tests/epsrv/src/main.rs` for what happened to the version that put the
/// serve loop in `uhello` and chose at runtime.
///
/// # The index-0 assumption, stated because it is one
///
/// `cap_lookup` matches a packed kind on the object's POOL INDEX, and ring 3
/// has **no by-name endpoint lookup** — `endpoint.demo` is the first endpoint
/// grant of the topology's rows and the boot creates them in that order before
/// anything is spawned, so it is index 0 (`tests/host/topology-tests` asserts
/// the order). The day an endpoint is declared ahead of it, this finds the
/// wrong object and the payload check is what will catch it. A by-name lookup
/// is the honest fix and is not built.
fn check_endpoint_exchange() {
    let cap = sys::cap_lookup(sys::ty::ENDPOINT.raw(), 0);
    expect_pos(b"cap_lookup(Endpoint, 0) finds the seeded endpoint.demo cap", cap);
    if cap <= 0 {
        return;
    }

    let srv = sys::spawn_ex(sys::cstr!(b"/fat/EPSRV.ELF"), None);
    expect_pos(b"spawn_ex(/fat/EPSRV.ELF) returns the server TID", srv);
    if srv <= 0 {
        return;
    }

    // M1, wave 9: `EPSRV.ELF`'s topology row declares no
    // `instances`, so one live instance is all it may have, and the one just
    // spawned is alive until it has served the call below. A second spawn of
    // the same image now must be refused (`-1`, not `EACCES`: the image is
    // bound, its row is full). The kernel prints the refusal with its count.
    let again = sys::spawn_ex(sys::cstr!(b"/fat/EPSRV.ELF"), None);
    report(
        b"spawn_ex(/fat/EPSRV.ELF) again while it lives -> refused (row instances = 1)",
        again < 0 && again != E_ACCES,
        again,
    );

    // The capability this call MOVES to the server.
    //
    // A `Cap<Socket>`, because `DOMAIN_SOCKET` mints one **into its
    // creator** — create-only minting, which owner decision 3 never
    // restricted — and this program already holds both that call and
    // `SYS_CAP_CLOSE`. The sensor and GPIO capabilities its topology row
    // grants would have needed syscalls outside its seccomp profile to prove
    // anything, and `sensor_info` is a kernel stub that always answers -1.
    let sock = sys::socket_typed(2, 2, 0); // AF_INET, SOCK_DGRAM
    expect_pos(b"socket_typed mints a Cap<Socket> to move", sock);
    let moving = if sock > 0 { sock as u32 } else { 0 };

    // A value with no zero bytes and no small-integer look to it, so a reply
    // of 0, of 1, or of the request echoed back all read as failures.
    const REQ: u64 = 0x5A5A_1234_DEAD_0000;
    let mut answered = false;
    // The kernel blocks this task until the server replies, so one call is
    // normally the whole story. The retry covers only the window before
    // `epsrv` reaches its accept — it is a freshly spawned sibling and may not
    // have been scheduled yet — and the bound stops this from hanging the row
    // if the server never arrives at all.
    let mut deadline = Deadline::in_ms(20_000);
    while !deadline.expired() {
        match sys::fast_ipc_call_ep_moving(cap as u32, [REQ, 0, 0, 0], moving)
            .map(|r| r[0])
        {
            Some(reply) => {
                expect_eq(
                    b"endpoint.demo answered w0+1 (the reply is THIS exchange's)",
                    reply as isize,
                    REQ.wrapping_add(1) as isize,
                );
                answered = true;
                break;
            }
            None => sys::yield_now(),
        }
    }
    report(b"endpoint.demo exchange completed", answered, answered as isize);

    // **The half that separates a MOVE from a COPY.** `epsrv` closed this very
    // capability, so if it were copied rather than moved this close would also
    // succeed. Owner decision 38 says the sender's entry is removed in the
    // same step the receiver's is installed; this is that sentence, asserted.
    if answered && moving != 0 {
        let after = sys::close_typed(moving);
        report(
            b"the moved Cap<Socket> no longer resolves for the SENDER",
            after < 0,
            after,
        );
    }

    // Reap the server, and read its verdict. `epsrv` exits 0 only after a
    // delivered request AND an accepted reply, so this is the server's own
    // half of the same exchange — the half the client cannot observe. A client
    // that somehow saw the right payload while the server reported a failure
    // would show up here and nowhere else.
    //
    // SLEEP, not yield, between looks (the child-footprint wait's reason):
    // this task (soft_rt 16) outranks `epsrv` (best_effort 24), and a yield
    // never hands the hart to a lower priority. Seen on a wave-9 integration
    // boot: `epsrv`, Ready after its reply, printed its last line only after
    // 100 000 yields here had run out. 2 000 x 2 ms bounds the wait at 4 s.
    let mut status: i32 = -12345;
    let mut got = -1isize;
    for _ in 0..2_000 {
        got = sys::waitpid(srv as u32, &mut status as *mut i32);
        if got != -1 { break; }
        sys::sleep(2);
    }
    expect_eq(b"waitpid(epsrv) returns its TID", got, srv);
    expect_eq(b"epsrv exits 0: it served the exchange", status as isize, 0);
}

// ── Process identity and memory ─────────────────────────────────────────────

fn check_process() {
    // A ring-3 task always has a real tid. If this is <= 0 the process is not
    // where the rest of the test assumes it is.
    expect_pos(b"getpid() > 0", sys::getpid());

    // `sys_meminfo` returns FREE PAGES, not bytes. The old doc said "total
    // memory in bytes"; a page count on any bootable configuration is > 0
    // and far below what a byte count would be.
    expect_pos(b"meminfo() > 0 (free PAGES, not bytes)", sys::meminfo());

    // `sys_uptime` is the raw CLINT mtime counter, NOT milliseconds. The
    // only portable assertion is monotonicity.
    let t0 = sys::uptime();
    sys::yield_now();
    let t1 = sys::uptime();
    expect_true(b"uptime() monotonic (raw CLINT ticks)", t1 >= t0 && t0 > 0);

    // Yield must return cleanly to ring 3.
    expect_eq(b"yield_now() returns", { sys::yield_now(); 0 }, 0);

    // `sys_wait` is `-1 // Phase 8+`. Documented as unimplemented; assert it
    // so the doc stops being true silently if someone implements it.
    // `wait()` is NO LONGER a stub, but with no children to reap it still
    // returns -1 — the correct answer, not a failure. The check that it DOES
    // reap a real child lives in `check_wait_reaps_child`.
    expect_err(b"wait() with no children -> -1 (correct, not a stub)", sys::wait());
}

// ── Console I/O byte counts ─────────────────────────────────────────────────

fn check_console_io() {
    // `sys_write` on fd 1/2 returns the count it was GIVEN (`return chunk as
    // i64` after `write_str_translated`), not the number of bytes the UART
    // emitted — LF-to-CRLF translation does not inflate the result. Since
    // MSG is well under the 4 KiB clamp, the answer must equal MSG.len().
    // This is the contract every other line of output in this file leans on.
    const MSG: &[u8] = b"[ABITEST] (write returns its input byte count)\n";
    let n = sys::write(sys::STDOUT, MSG);
    expect_eq(b"write(STDOUT) returns MSG.len()", n, MSG.len() as isize);
}

// ── NUL-terminated path contract ────────────────────────────────────────────

fn check_paths_and_nul() {
    // The kernel reads paths with `copy_cstr_from_user`, which scans for a
    // NUL and never sees the slice length. This is the real bug found on
    // 2026-08-21 in brain_client.

    // A path with no terminator must be rejected BY THE WRAPPER, before the
    // ecall, so the kernel never scans past the literal.
    expect_eq(
        b"open(unterminated) -> E_INVAL from libsys",
        sys::open_root(b"/fat/NOT_TERMINATED", 0),
        sys::E_INVAL,
    );
    expect_eq(
        b"mkdir(unterminated) -> E_INVAL from libsys",
        sys::mkdir(b"/nope"),
        sys::E_INVAL,
    );

    // A properly terminated path reaches the kernel and gets a kernel answer
    // (not E_INVAL). Asserting a *missing* file keeps this independent of
    // whether a FAT32 image is attached — `qemu-smp` has no disk.
    let rc = sys::open_root(sys::cstr!(b"/definitely/not/here"), 0);
    expect_true(
        b"open(cstr!, missing) reaches kernel, fails there",
        rc < 0 && rc != sys::E_INVAL,
    );

    // `cstr!` must append exactly one NUL and keep the body intact. Checking
    // the macro's own output is what makes it trustworthy at every call site.
    const P: &[u8] = sys::cstr!(b"/fat/X");
    expect_true(
        b"cstr! appends exactly one NUL",
        P.len() == 7 && P[6] == 0 && P[0] == b'/' && P[5] == b'X',
    );
    expect_true(b"has_nul() agrees with cstr! output", sys::has_nul(P));
    expect_true(b"has_nul() rejects a bare literal", !sys::has_nul(b"/fat/X"));

    // The kernel's predicate is "contains a NUL", not "ends with one" — a
    // scratch buffer with trailing slack is legal and must not be rejected.
    let mut padded = [0u8; 32];
    padded[0] = b'/';
    padded[1] = b'x';
    expect_true(b"has_nul() accepts NUL + trailing slack", sys::has_nul(&padded));
}

// ── vDSO: the zero-ecall path, and the offset bug it once hid ───────────────

fn check_vdso() {
    // `vdso_uptime_ticks` read byte offset 8 — the seqlock counter — instead
    // of 16 for a long time. `seq` advances by 2 per publish, so it still
    // looked like a plausible monotonic counter, which is exactly why the
    // bug survived. Monotonicity alone does NOT catch it.
    //
    // What the two fields actually are (the vDSO update in kernel/src/entry/riscv64/irq.rs):
    //   uptime_ticks (offset 16) = TICK_COUNT, one per timer INTERRUPT.
    //   uptime_ms    (offset 24) = clint_now / (TIMER_FREQ / 1000).
    // They run at different rates, and which is larger depends on the
    // scheduler frequency — so an ordering assertion between them would be
    // a guess. The rate check below targets `uptime_ms` alone, where the
    // expected rate IS known: one unit per millisecond.

    let ms0 = sys::vdso_uptime_ms();
    let t0 = sys::vdso_uptime_ticks();
    // Nonzero implies the magic matched — `vdso_read_u64` returns 0 outright
    // on a bad or unmapped page.
    expect_true(b"vdso page mapped + magic ok (ms nonzero)", ms0 != 0);
    expect_true(b"vdso uptime_ticks nonzero", t0 != 0);
    expect_true(b"vdso kernel_version nonzero", sys::vdso_kernel_version() != 0);

    // Burn a known wall-clock interval, then check `uptime_ms` moved by
    // about that many units. This is the assertion the offset bug fails:
    // the seqlock counter advances a couple of units per timer interrupt,
    // nowhere near one per millisecond. The window is deliberately wide
    // (>= 20, <= 5000 for a 50 ms sleep) — it is checking the field's
    // *units*, not the host's timekeeping accuracy.
    const SLEEP_MS: u64 = 50;
    sys::sleep(SLEEP_MS);
    let ms1 = sys::vdso_uptime_ms();
    let t1 = sys::vdso_uptime_ticks();

    expect_true(b"vdso ms monotonic", ms1 >= ms0);
    expect_true(b"vdso ticks monotonic", t1 >= t0);

    // `saturating_sub`, not `-`: the assertions above REPORT non-monotonicity,
    // they do not prevent it. Under `overflow-checks = true` a plain
    // subtraction on a failing kernel would underflow, and `panic = "abort"`
    // turns that into a board reset — a diagnostic tool must not brick the
    // board it is diagnosing.
    let d_ms = ms1.saturating_sub(ms0);
    let d_ticks = t1.saturating_sub(t0);
    expect_true(
        b"vdso uptime_ms really counts MILLISECONDS",
        d_ms >= SLEEP_MS / 2 && d_ms <= SLEEP_MS * 100,
    );
    out(b"[ABITEST]        vdso d_ms over 50ms sleep = ");
    print_i(d_ms as isize);
    out(b", d_ticks = ");
    print_i(d_ticks as isize);
    out(b"\n");

    // The tick field must be a live counter, not a frozen value: the timer
    // interrupt fires many times during a 50 ms sleep.
    expect_true(b"vdso uptime_ticks advanced during sleep", t1 > t0);

    // DOMAIN_UPTIME is the raw CLINT mtime counter (~10 MHz) while the vDSO
    // tick field counts interrupts, so the ecall value is necessarily the
    // larger of the two. This pins the fact that they are DIFFERENT clocks —
    // a caller cannot substitute one for the other.
    let ecall = sys::uptime_ecall();
    expect_true(
        b"uptime_ecall() is CLINT ticks, not vdso interrupt count",
        ecall > 0 && (ecall as u64) > t1,
    );
}

/// The vDSO hwcap word (`sys::vdso_hwcap`, the AT_HWCAP analogue): printed
/// as `[ABITEST] hwcap=0x...` for the gate to compare with the kernel's
/// `[VDSO] hwcap=` line, and checked from ring 3:
///   * every set bit is one this ISA defines (`hwcap::HWCAP_*_ALL`: each
///     ISA numbers its own bits from 0);
///   * the page is layout version 1 and its `hwcap2` word reads 0 (reserved:
///     no ISA defines a bit there yet);
///   * x86_64: every set bit is one CPUID also reports (CPUID is legal in
///     ring 3), with the OS enable CPUID reflects where there is one
///     (OSXSAVE + XCR0 YMM for AVX2/FMA, OSPKE for PKU);
///   * x86_64: the instruction behind every set bit runs here. One that
///     #UDs kills abitest before its summary, which fails the row.
/// The expected set under a given QEMU `-cpu` is the gate's to state, not
/// this program's: real hardware may lack any of them.
fn check_hwcap() {
    let h = sys::vdso_hwcap();
    out(b"[ABITEST] hwcap=0x");
    let mut buf = [0u8; 16];
    for (i, b) in buf.iter_mut().enumerate() {
        let nib = ((h >> (60 - 4 * i)) & 0xF) as u8;
        *b = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
    }
    let first = buf.iter().position(|&b| b != b'0').unwrap_or(15);
    out(&buf[first..]);
    out(b"\n");
    #[cfg(target_arch = "riscv64")]
    let all = sys::hwcap::HWCAP_RV_ALL;
    #[cfg(target_arch = "aarch64")]
    let all = sys::hwcap::HWCAP_A64_ALL;
    #[cfg(target_arch = "x86_64")]
    let all = sys::hwcap::HWCAP_X86_ALL;
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
    let all = 0u64;
    expect_true(b"hwcap: every set bit is one this ISA defines", h & !all == 0);
    #[cfg(not(target_arch = "x86_64"))]
    pmu_user_reads(h);
    // 2: version 1 plus the clock words (`azos_abi::vdso::VDSO_LAYOUT_VERSION`); a literal so that a
    // layout change must be made here on purpose.
    expect_true(b"vdso layout version is 2", sys::vdso_layout_version() == 2);
    expect_true(b"vdso publishes the ABI version this program was built against", sys::abi_matches());
    expect_true(b"vdso hwcap2 (reserved) reads 0", sys::vdso_hwcap2() == 0);
    // arch-only: x86_64 cross-checks hwcap against CPUID (legal in ring 3); aarch64's ID registers and riscv64's ISA string are not readable from ring 3.
    #[cfg(target_arch = "x86_64")]
    {
        expect_true(b"hwcap: every set bit is one CPUID reports, OS enable included", x86_hwcap_cpuid_mismatch(h) == 0);
        let ran = x86_hwcap_run(h);
        expect_true(b"hwcap: the instruction behind every set bit ran in ring 3", ran == (h & sys::hwcap::HWCAP_X86_ALL).count_ones());
    }
}

/// The counters the hwcap PMU bits publish are readable from ring 3: a read
/// the kernel did not open would trap and kill abitest before its summary, so
/// this row going red is the missing-`scounteren` / missing-`PMUSERENR_EL0`
/// canary. x86_64 does the same inside `x86_hwcap_run`.
// arch-only: the counter registers are named per ISA; x86_64's `rdpmc` is in `x86_hwcap_run`.
#[cfg(not(target_arch = "x86_64"))]
fn pmu_user_reads(h: u64) {
    #[cfg(target_arch = "riscv64")]
    let (cycles_bit, instr_bit) = (sys::hwcap::HWCAP_RV_PMU_CYCLES, sys::hwcap::HWCAP_RV_PMU_INSTR);
    #[cfg(target_arch = "aarch64")]
    let (cycles_bit, instr_bit) = (sys::hwcap::HWCAP_A64_PMU_CYCLES, sys::hwcap::HWCAP_A64_PMU_INSTR);
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
    let (cycles_bit, instr_bit) = (0u64, 0u64);
    let mut ran = 0u32;
    // SAFETY (both blocks): a read of the counter the hwcap bit publishes as
    // open to ring 3; no memory is touched.
    if h & cycles_bit != 0 {
        #[cfg(target_arch = "riscv64")]
        unsafe { core::arch::asm!("rdcycle {0}", out(reg) _, options(nomem, nostack)) };
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("mrs {0}, PMCCNTR_EL0", out(reg) _, options(nomem, nostack)) };
        #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
        {}
        ran += 1;
    }
    if h & instr_bit != 0 {
        #[cfg(target_arch = "riscv64")]
        unsafe { core::arch::asm!("rdinstret {0}", out(reg) _, options(nomem, nostack)) };
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("mrs {0}, PMEVCNTR0_EL0", out(reg) _, options(nomem, nostack)) };
        #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
        {}
        ran += 1;
    }
    expect_true(b"hwcap: the counter behind every PMU bit read in ring 3", ran == (h & (cycles_bit | instr_bit)).count_ones());
}

/// The set bits of `h` CPUID does not back (0 = none).
// arch-only: x86_64 cross-checks hwcap against CPUID (legal in ring 3); aarch64's ID registers and riscv64's ISA string are not readable from ring 3.
#[cfg(target_arch = "x86_64")]
fn x86_hwcap_cpuid_mismatch(h: u64) -> u64 {
    use core::arch::x86_64::{__cpuid_count, _xgetbv};
    let max = __cpuid_count(0, 0).eax;
    let max_ext = __cpuid_count(0x8000_0000, 0).eax;
    let l1 = __cpuid_count(1, 0);
    let l7 = if max >= 7 { __cpuid_count(7, 0) } else { __cpuid_count(0, 0) };
    let (b7, c7, d7) = if max >= 7 { (l7.ebx, l7.ecx, l7.edx) } else { (0, 0, 0) };
    let e7 = if max_ext >= 0x8000_0007 { __cpuid_count(0x8000_0007, 0).edx } else { 0 };
    let has = |w: u32, b: u32| w & (1 << b) != 0;
    // OSXSAVE (CPUID.1:ECX[27]) mirrors CR4.OSXSAVE: XGETBV is legal then.
    // SAFETY: XGETBV with ECX=0 in ring 3, gated on OSXSAVE.
    let ymm = has(l1.ecx, 27) && unsafe { _xgetbv(0) } & 0b110 == 0b110;
    let table: [(u64, bool); 18] = [
        (sys::hwcap::HWCAP_X86_SSE4_2, has(l1.ecx, 20)),
        (sys::hwcap::HWCAP_X86_POPCNT, has(l1.ecx, 23)),
        (sys::hwcap::HWCAP_X86_AVX2, has(b7, 5) && ymm),
        (sys::hwcap::HWCAP_X86_BMI1, has(b7, 3)),
        (sys::hwcap::HWCAP_X86_BMI2, has(b7, 8)),
        (sys::hwcap::HWCAP_X86_FMA, has(l1.ecx, 12) && ymm),
        (sys::hwcap::HWCAP_X86_MOVBE, has(l1.ecx, 22)),
        (sys::hwcap::HWCAP_X86_AES, has(l1.ecx, 25)),
        (sys::hwcap::HWCAP_X86_PCLMULQDQ, has(l1.ecx, 1)),
        (sys::hwcap::HWCAP_X86_SHA_NI, has(b7, 29)),
        (sys::hwcap::HWCAP_X86_RDRAND, has(l1.ecx, 30)),
        (sys::hwcap::HWCAP_X86_RDSEED, has(b7, 18)),
        (sys::hwcap::HWCAP_X86_ADX, has(b7, 19)),
        (sys::hwcap::HWCAP_X86_FSGSBASE, has(b7, 0)),
        // OSPKE (CPUID.7:ECX[4]) mirrors CR4.PKE.
        (sys::hwcap::HWCAP_X86_PKU, has(c7, 3) && has(c7, 4)),
        (sys::hwcap::HWCAP_X86_CET_IBT, has(d7, 20)),
        (sys::hwcap::HWCAP_X86_CET_SHSTK, has(c7, 7)),
        (sys::hwcap::HWCAP_X86_INVARIANT_TSC, has(e7, 8)),
    ];
    let mut backed = 0u64;
    for (bit, on) in table {
        if on {
            backed |= bit;
        }
    }
    // The PMU bits are the kernel's to publish (a live counter, Kconfig PMU_USER,
    // `CR4.PCE`), not a CPUID feature: `x86_hwcap_run` proves them by reading.
    let kernel_owned = sys::hwcap::HWCAP_X86_PMU_CYCLES | sys::hwcap::HWCAP_X86_PMU_INSTR | sys::hwcap::HWCAP_X86_PMU_FIXED;
    h & sys::hwcap::HWCAP_X86_ALL & !backed & !kernel_owned
}

/// Run the instruction behind each set bit; returns how many ran.
// arch-only: x86_64 cross-checks hwcap against CPUID (legal in ring 3); aarch64's ID registers and riscv64's ISA string are not readable from ring 3.
#[cfg(target_arch = "x86_64")]
fn x86_hwcap_run(h: u64) -> u32 {
    use core::arch::asm;
    let mut ran = 0u32;
    let mut on = |bit: u64| {
        let set = h & bit != 0;
        if set {
            ran += 1;
        }
        set
    };
    let (mut a, b): (u64, u64) = (0x1234_5678, 0x0f0f_0f0f);
    let word: u32 = 0x1122_3344;
    // SAFETY (every block): one unprivileged instruction the hwcap bit says
    // this CPU has and the kernel enabled for ring 3; the clobbers name
    // every register it writes.
    unsafe {
        if on(sys::hwcap::HWCAP_X86_SSE4_2) {
            asm!("crc32 {0:e}, {1:e}", inout(reg) a, in(reg) b, options(nomem, nostack));
        }
        if on(sys::hwcap::HWCAP_X86_POPCNT) {
            asm!("popcnt {0}, {1}", out(reg) a, in(reg) b, options(nomem, nostack));
        }
        if on(sys::hwcap::HWCAP_X86_AVX2) {
            asm!("vpaddd ymm0, ymm0, ymm0", "vzeroupper", out("xmm0") _, options(nomem, nostack, preserves_flags));
        }
        if on(sys::hwcap::HWCAP_X86_BMI1) {
            asm!("andn {0}, {1}, {1}", out(reg) a, in(reg) b, options(nomem, nostack));
        }
        if on(sys::hwcap::HWCAP_X86_BMI2) {
            asm!("pdep {0}, {1}, {1}", out(reg) a, in(reg) b, options(nomem, nostack, preserves_flags));
        }
        if on(sys::hwcap::HWCAP_X86_FMA) {
            asm!("vfmadd231ps xmm0, xmm0, xmm0", out("xmm0") _, options(nomem, nostack, preserves_flags));
        }
        if on(sys::hwcap::HWCAP_X86_MOVBE) {
            let p = &word as *const u32;
            asm!("movbe {0:e}, dword ptr [{1}]", out(reg) a, in(reg) p, options(readonly, nostack, preserves_flags));
        }
        if on(sys::hwcap::HWCAP_X86_AES) {
            asm!("aesenc xmm0, xmm0", out("xmm0") _, options(nomem, nostack, preserves_flags));
        }
        if on(sys::hwcap::HWCAP_X86_PCLMULQDQ) {
            asm!("pclmulqdq xmm0, xmm0, 0", out("xmm0") _, options(nomem, nostack, preserves_flags));
        }
        if on(sys::hwcap::HWCAP_X86_SHA_NI) {
            asm!("sha256msg1 xmm0, xmm1", out("xmm0") _, out("xmm1") _, options(nomem, nostack, preserves_flags));
        }
        if on(sys::hwcap::HWCAP_X86_RDRAND) {
            asm!("rdrand {0}", out(reg) a, options(nomem, nostack));
        }
        if on(sys::hwcap::HWCAP_X86_RDSEED) {
            asm!("rdseed {0}", out(reg) a, options(nomem, nostack));
        }
        if on(sys::hwcap::HWCAP_X86_ADX) {
            asm!("adcx {0}, {1}", inout(reg) a, in(reg) b, options(nomem, nostack));
        }
        if on(sys::hwcap::HWCAP_X86_FSGSBASE) {
            asm!("rdfsbase {0}", out(reg) a, options(nomem, nostack, preserves_flags));
        }
        if on(sys::hwcap::HWCAP_X86_PKU) {
            asm!("rdpkru", in("ecx") 0u32, out("eax") _, out("edx") _, options(nomem, nostack, preserves_flags));
        }
        if on(sys::hwcap::HWCAP_X86_CET_IBT) {
            asm!("endbr64", options(nomem, nostack, preserves_flags));
        }
        if on(sys::hwcap::HWCAP_X86_CET_SHSTK) {
            asm!("rdsspq {0}", inout(reg) a, options(nomem, nostack, preserves_flags));
        }
        if on(sys::hwcap::HWCAP_X86_INVARIANT_TSC) {
            asm!("rdtsc", out("eax") _, out("edx") _, options(nomem, nostack, preserves_flags));
        }
        // The PMU counters (Kconfig PMU_USER, `CR4.PCE`): `rdpmc` at the index
        // PMU_FIXED names; without PCE it is a #GP that kills abitest.
        let fixed: u32 = if h & sys::hwcap::HWCAP_X86_PMU_FIXED != 0 { 1 << 30 } else { 0 };
        if on(sys::hwcap::HWCAP_X86_PMU_CYCLES) {
            let idx = if fixed != 0 { fixed | 1 } else { 0 };
            asm!("rdpmc", in("ecx") idx, out("eax") _, out("edx") _, options(nomem, nostack, preserves_flags));
        }
        if on(sys::hwcap::HWCAP_X86_PMU_INSTR) {
            let idx = if fixed != 0 { fixed } else { 1 };
            asm!("rdpmc", in("ecx") idx, out("eax") _, out("edx") _, options(nomem, nostack, preserves_flags));
        }
        // An index scheme, not an instruction: it ran if it was published.
        on(sys::hwcap::HWCAP_X86_PMU_FIXED);
    }
    core::hint::black_box(a);
    ran
}

/// `uptime()` reads the counter without a trap where `rdtime` is native
///.
///
/// Three claims, each caught by a different mistake:
///
///   * **The kernel published the flag.** The QEMU kernel sets vDSO `flags`
///     bit 0; one built to force the trap (or one that never calls
///     `vdso_set_flags`) leaves it clear, and this line fails.
///   * **One counter.** An `rdtime` read taken between two `DOMAIN_UPTIME` reads
///     lies between them. `uptime()` wired to the page's `uptime_ticks` — an
///     interrupt count, orders of magnitude smaller — fails the lower bound.
///   * **No trap.** The bracket passes just as well against an `uptime()`
///     that still issues the `ecall`, since it returns the same counter. What
///     a trap changes from ring 3 is the cost, so the cheapest of eight
///     batches of each is compared: under QEMU TCG a trapped read costs tens
///     of times an `rdtime`, and the check asks only for half. The minimum
///     over batches drops a batch a preemption landed in.
fn check_uptime_without_a_trap() {
    let native = sys::vdso_rdtime_native();
    expect_true(b"vdso flags bit 0: rdtime native (the QEMU kernel sets it)", native);

    let lo = sys::uptime_ecall();
    let mid = sys::uptime();
    let hi = sys::uptime_ecall();
    report(
        b"uptime_ecall() <= uptime() <= uptime_ecall() (one counter)",
        lo > 0 && lo <= mid && mid <= hi,
        mid,
    );

    if !native {
        return;
    }
    const BATCHES: usize = 8;
    const CALLS: u32 = 64;
    let mut best_page = u64::MAX;
    let mut best_trap = u64::MAX;
    for _ in 0..BATCHES {
        let t0 = sys::vdso_now_ns();
        for _ in 0..CALLS { core::hint::black_box(sys::uptime()); }
        let t1 = sys::vdso_now_ns();
        for _ in 0..CALLS { core::hint::black_box(sys::uptime_ecall()); }
        let t2 = sys::vdso_now_ns();
        best_page = best_page.min(t1.saturating_sub(t0));
        best_trap = best_trap.min(t2.saturating_sub(t1));
    }
    out(b"[ABITEST]        64 x uptime() = ");
    print_i(best_page as isize);
    out(b" ns, 64 x uptime_ecall() = ");
    print_i(best_trap as isize);
    out(b" ns (cheapest of 8)\n");
    expect_true(
        b"uptime() costs under half of the uptime op: no trap",
        best_page.saturating_mul(2) < best_trap,
    );
}

// ── Sleep: blocking, absolute, and never early ───────────────────

/// This task's voluntary context switches so far: `DOMAIN_TASKINFO` slot 2, which
/// the scheduler counts where a task actually gives up the CPU to yield or
/// block, and nowhere else.
fn voluntary_switches() -> u64 {
    let mut ti = [0u8; sys::TASKINFO_BYTES];
    if sys::taskinfo(&mut ti) != sys::TASKINFO_BYTES as isize {
        return 0;
    }
    u64::from_le_bytes([ti[16], ti[17], ti[18], ti[19], ti[20], ti[21], ti[22], ti[23]])
}

fn sleep_rc(r: sys::SleepResult) -> isize {
    match r {
        sys::SleepResult::Slept => 0,
        sys::SleepResult::Overrun => 1,
        sys::SleepResult::Refused(rc) => rc,
    }
}

/// `SYS_SLEEP_UNTIL` and `SYS_SLEEP_UNTIL` block the caller.
///
/// **Blocking against spinning, from ring 3.** `SYS_SLEEP_UNTIL` used to loop on
/// the counter inside the syscall. A spinning sleep and a blocking one return
/// at the same time; what differs is whether the task gave the CPU away.
/// Blocking goes through `block_current`, which switches with
/// `SwitchReason::Voluntary` and so adds to `DOMAIN_TASKINFO`'s voluntary count;
/// a loop inside the syscall adds nothing there, since the timer can only
/// preempt it, which counts in the other slot. So each sleep below is
/// bracketed by that count, with no other call inside the bracket that could
/// yield.
///
/// **Deadlines.** The kernel converts a deadline to ticks rounding up, and
/// `vdso_now_ns` converts ticks back rounding down with the same frequency, so
/// every return reads at or after its deadline.
///
/// **How late is NOT judged here (wave 13).** This check used to require the
/// last wake within two ticks (20 ms) of its deadline. On QEMU the guest clock
/// is the host's, so a vCPU the host descheduled reads as a late wake: the
/// aarch64 row read 24.6 ms with the timer heap and 20.3 ms without it, at
/// host loads 2-11, with nothing late in the kernel. What is checked instead
/// is the condition, once the clock has passed the deadline: the last sleep
/// WOKE on its own timer (`Slept`, read at or after its deadline; this task
/// has no other wake source). That the sleeps block is the voluntary-switch
/// check above it; requiring a switch of the LAST one alone would fail when
/// its deadline passes between the entry check and the block. Wake latency is measured where it can be — under `-icount`, in the
/// `lat:` rows (bound 100 us) and vsbench's `timer-periodic` lane.
fn check_sleep_blocks() {
    let hz = sys::vdso_timebase_hz();
    expect_true(b"vdso publishes the timebase (the sleep checks read the clock)", hz != 0);
    if hz == 0 {
        return;
    }

    // SYS_SLEEP_UNTIL (15), relative milliseconds.
    const SLEEP_MS: u64 = 20;
    let v0 = voluntary_switches();
    let t0 = sys::vdso_now_ns();
    sys::sleep(SLEEP_MS);
    let t1 = sys::vdso_now_ns();
    let v1 = voluntary_switches();
    let elapsed = t1.saturating_sub(t0);
    report(b"sleep(20) returns no earlier than 20 ms (us)",
           elapsed >= SLEEP_MS * 1_000_000, (elapsed / 1_000) as isize);
    report(b"sleep(20) BLOCKS: >= 1 voluntary switch (a busy-wait makes 0)",
           v1 > v0, v1.saturating_sub(v0) as isize);

    // A deadline long past answers Overrun, without blocking.
    let v2 = voluntary_switches();
    let r = sys::sleep_until_ns(1);
    let v3 = voluntary_switches();
    report(b"sleep_until_ns(past) -> Overrun (1)", r == sys::SleepResult::Overrun, sleep_rc(r));
    report(b"sleep_until_ns(past) did not block: 0 voluntary switches",
           v3 == v2, v3.saturating_sub(v2) as isize);

    // 100 periods of 10 ms, `next += period`.
    const PERIODS: u32 = 100;
    const PERIOD_NS: u64 = 10_000_000;
    let mut slept = 0u64;
    let mut overrun = 0u64;
    let mut early = 0u64;
    let mut refused = 0isize;
    let mut max_late = 0u64;
    let mut last_wake_late = u64::MAX;
    // The last sleep: (result was Slept, read at or after its deadline).
    let mut last = (false, false);
    let v4 = voluntary_switches();
    let mut next = sys::vdso_now_ns().saturating_add(PERIOD_NS);
    for _ in 0..PERIODS {
        let r = sys::sleep_until_ns(next);
        let now = sys::vdso_now_ns();
        last = (r == sys::SleepResult::Slept, now >= next);
        let late = now.saturating_sub(next);
        if now < next {
            early += 1;
        }
        match r {
            sys::SleepResult::Slept => {
                slept += 1;
                last_wake_late = late;
            }
            sys::SleepResult::Overrun => overrun += 1,
            sys::SleepResult::Refused(rc) => {
                refused = rc;
                break;
            }
        }
        max_late = max_late.max(late);
        next = next.saturating_add(PERIOD_NS);
    }
    // The last sleep is judged on a deadline taken now, not on the fixed
    // grid: a grid wake late by more than one period (the host descheduled
    // the vCPU) leaves the next grid deadline already past, and that call
    // rightly answers Overrun. A fresh deadline can only be missed if the
    // sleep itself is broken.
    if refused == 0 {
        let fresh = sys::vdso_now_ns().saturating_add(PERIOD_NS);
        let r = sys::sleep_until_ns(fresh);
        let now = sys::vdso_now_ns();
        last = (r == sys::SleepResult::Slept, now >= fresh);
        last_wake_late = now.saturating_sub(fresh);
    }
    let v5 = voluntary_switches();
    let vol = v5.saturating_sub(v4);

    out(b"[ABITEST]        100 x 10 ms: slept ");
    print_i(slept as isize);
    out(b", overrun ");
    print_i(overrun as isize);
    out(b", voluntary switches ");
    print_i(vol as isize);
    out(b", max late ");
    print_i((max_late / 1_000) as isize);
    out(b" us\n");

    expect_eq(b"sleep_until_ns() answered, not refused", refused, 0);
    report(b"every sleep_until_ns() return reads vdso_now_ns() >= its deadline",
           early == 0, early as isize);
    // Half, not all: a wait can end without a switch when the deadline passes
    // between the call's entry check and its block. A busy-wait makes none.
    report(b"sleep_until_ns() BLOCKS: voluntary switches >= slept/2 (a busy-wait makes 0)",
           slept > 0 && vol >= (slept / 2).max(1), vol as isize);
    // The value printed is the last wake's lateness (us), for the record.
    report(b"the last sleep woke on its timer, at or after its deadline (late us)",
           last.0 && last.1,
           (last_wake_late.min(i64::MAX as u64) / 1_000) as isize);
}

// ── Syscalls the kernel answers with sys_stub() ─────────────────────────────

/// Connected UDP + local delivery, from ring 3.
///
/// **These three paths did not exist until 2026-08-30**, and each failed on
/// its own:
///
///   * `ip::send` sent a destination equal to our own IP to the wire, where it
///     died in ARP because nobody answers for itself.
///   * `socket_connect` refused anything that was not TCP.
///   * `socket_send` too — and `sendto` in this ABI **carried no address**, so
///     a UDP socket had no way at all to name a destination: it was
///     receive-only.
///
/// Checked here, from ring 3, because the kernel's boot smoke exercises the
/// internal path and **not** the syscall crossing: the first version of this
/// worked in the kernel and failed from userspace, on a second TCP-only gate
/// (`socket_connect_with_yield`) that the syscall path uses and the internal
/// one does not.
fn check_udp_loopback() {
    let raw = sys::net_getip();
    if raw <= 0 {
        // With no IP assigned, local delivery is deliberately off, so there is
        // nothing to assert. Say so rather than count a success.
        outln(b"[ABITEST] (no IP: UDP loopback not checked)");
        return;
    }
    let ip = (raw as u32).to_be_bytes();
    const PORT: u16 = 7311;

    let rx = sys::socket_typed(2, 2, 0);   // AF_INET, SOCK_DGRAM
    let tx = sys::socket_typed(2, 2, 0);
    // **`>= 0`, not `> 0`.** The first version used `expect_pos` and failed
    // with `rc=0`: descriptor 0 is a perfectly valid socket. It was the
    // assertion that was wrong, not the kernel — worth writing down, because
    // `expect_pos` is what the eye reaches for and here it is incorrect.
    expect_true(b"socket(AF_INET, SOCK_DGRAM) rx", rx >= 0);
    expect_true(b"socket(AF_INET, SOCK_DGRAM) tx", tx >= 0);
    if rx < 0 || tx < 0 { return; }

    let addr = sys::sockaddr_in(ip, PORT);
    expect_eq(b"bind() a UDP socket", sys::bind_typed(rx as u32, &addr), 0);
    expect_eq(b"connect() over UDP (TCP-only before)", sys::connect_typed(tx as u32, &addr), 0);

    const PAYLOAD: &[u8] = b"abitest-udp";
    expect_eq(
        b"send() over UDP returns BYTES, not 0",
        sys::send_typed(tx as u32, PAYLOAD),
        PAYLOAD.len() as isize,
    );

    // The datagram travels through the stack; polled with yield because
    // `recv` does not block on this kernel.
    let mut buf = [0u8; 32];
    let mut got = -1isize;
    let mut deadline = Deadline::in_ms(5_000);
    while !deadline.expired() {
        got = sys::recv_typed(rx as u32, &mut buf);
        if got > 0 { break; }
        sys::yield_now();
    }
    expect_eq(b"recv() receives the local datagram", got, PAYLOAD.len() as isize);
    expect_true(
        b"payload survives local delivery",
        got > 0 && &buf[..got as usize] == PAYLOAD,
    );

    // ── UNCONNECTED UDP: sendto with destination, recvfrom with sender ──
    //
    // **This did not exist until 2026-08-30.** `NODE_SENDTO` dispatched to the
    // same place as `NODE_SEND` and lost the address; `NODE_RECVFROM` likewise
    // with the sender. The UDP machinery below already supported it —
    // `udp::sendto` and `udp::recvfrom` have taken that data all along — and
    // the syscall layer threw it away.
    //
    // Without this a UDP server cannot answer whoever speaks to it: it
    // receives the datagram and does not know where it came from.
    let srv = sys::socket_typed(2, 2, 0);
    expect_true(b"socket() for the unconnected server", srv >= 0);
    if srv >= 0 {
        const P_SRV: u16 = 7312;
        let srv_addr = sys::sockaddr_in(ip, P_SRV);
        expect_eq(b"bind() the server", sys::bind_typed(srv as u32, &srv_addr), 0);

        // Sent WITHOUT connect, naming the destination in the call itself.
        let cli = sys::socket_typed(2, 2, 0);
        if cli >= 0 {
            let cli_addr = sys::sockaddr_in(ip, 7313);
            expect_eq(b"bind() the client", sys::bind_typed(cli as u32, &cli_addr), 0);
            const M: &[u8] = b"no-connect";
            expect_eq(
                b"sendto() WITH destination, no prior connect",
                sys::sendto_typed(cli as u32, M, Some(&srv_addr)),
                M.len() as isize,
            );

            let mut b2 = [0u8; 32];
            let mut sender = [0u8; sys::SOCKADDR_LEN];
            let mut n = -1isize;
            let mut deadline = Deadline::in_ms(5_000);
            while !deadline.expired() {
                n = sys::recvfrom_typed(srv as u32, &mut b2, Some(&mut sender));
                if n > 0 { break; }
                sys::yield_now();
            }
            expect_eq(b"recvfrom() delivers the datagram", n, M.len() as isize);
            // The sender must be the client's port, in network order.
            let sender_port = ((sender[2] as u16) << 8) | sender[3] as u16;
            expect_eq(b"recvfrom() REPORTS the sender", sender_port as isize, 7313);
            expect_true(
                b"sender IP is the local one",
                sender[4..8] == ip,
            );
            sys::close_typed(cli as u32);
        }
        sys::close_typed(srv as u32);
    }

    // ── Cap<Socket>: the same loopback, through capabilities ────────────
    //
    // Every socket call, on a real datagram, through the capability that names
    // the socket.
    {
        const E_CAPSTALE: isize = -202;
        const E_INVAL: isize = -22;
        const P_TYPED: u16 = 7314;
        const TP: &[u8] = b"abitest-typed";

        let trx = sys::socket_typed(2, 2, 0);
        let ttx = sys::socket_typed(2, 2, 0);
        expect_true(b"socket_typed(AF_INET, SOCK_DGRAM) rx", trx >= 0);
        expect_true(b"socket_typed(AF_INET, SOCK_DGRAM) tx", ttx >= 0);
        if trx >= 0 && ttx >= 0 {
            let taddr = sys::sockaddr_in(ip, P_TYPED);
            expect_eq(b"bind_typed() the socket behind a Cap<Socket>",
                      sys::bind_typed(trx as u32, &taddr), 0);
            expect_eq(b"connect_typed() over UDP", sys::connect_typed(ttx as u32, &taddr), 0);
            expect_eq(b"send_typed() returns bytes",
                      sys::send_typed(ttx as u32, TP), TP.len() as isize);

            let mut tbuf = [0u8; 32];
            let mut tgot = -1isize;
            let mut deadline = Deadline::in_ms(5_000);
            while !deadline.expired() {
                tgot = sys::recv_typed(trx as u32, &mut tbuf);
                if tgot > 0 { break; }
                sys::yield_now();
            }
            expect_eq(b"recv_typed() receives it",
                      tgot, TP.len() as isize);
            expect_true(b"typed payload survives local delivery",
                        tgot > 0 && &tbuf[..tgot as usize] == TP);

            expect_eq(b"close_typed(rx)", sys::close_typed(trx as u32), 0);
            expect_eq(b"close_typed(tx)", sys::close_typed(ttx as u32), 0);
            expect_eq(b"recv_typed() after close_typed [stale]",
                      sys::recv_typed(trx as u32, &mut tbuf), E_CAPSTALE);
        }
        // A forged Socket handle: the kind bits of a socket (`CapHandle::KIND_SHIFT` = 26) over
        // a slot this image never granted. It reaches the table and is refused as stale. Handle
        // 0 is the Null kind: an op of another kind than its handle's is `-EINVAL`
        // (`azos_abi::invoke`), before any table is consulted.
        let forged_sock = (sys::ty::SOCKET.raw() as u32) << 26 | 0x1FF;
        expect_eq(b"send_typed(forged Socket handle) [forged cap]",
                  sys::send_typed(forged_sock, b"x"), E_CAPSTALE);
        expect_eq(b"send_typed(0) [null handle]", sys::send_typed(0, b"x"), E_INVAL);
    }

    // ── Cap<Socket> multicast: join, loop back, leave ───────────────────
    //
    // A group datagram sent by this task reaches this task's own member: the
    // kernel delivers multicast to a joined group locally (`ip::send`) and
    // then sends the wire copy. That copy has no NIC to leave by in the ABI
    // scenario, and `ip::send` answers for the wire, so the send may report -1
    // there while the local delivery still happens. The receive is the
    // assertion; the send only has to be one of its two honest answers.
    {
        const E_INVAL: isize = -22;
        const GROUP: [u8; 4] = [239, 1, 2, 3];
        const P_MCAST: u16 = 7315;
        const MP: &[u8] = b"abitest-group";

        let mrx = sys::socket_typed(2, 2, 0);
        let mtx = sys::socket_typed(2, 2, 0);
        expect_true(b"socket_typed() multicast rx", mrx >= 0);
        expect_true(b"socket_typed() multicast tx", mtx >= 0);
        if mrx >= 0 && mtx >= 0 {
            expect_eq(b"bind() the multicast rx",
                      sys::bind_typed(mrx as u32, &sys::sockaddr_in(ip, P_MCAST)), 0);
            expect_eq(b"mcast_join_typed(239.1.2.3)", sys::mcast_join_typed(mrx as u32, GROUP), 0);
            expect_eq(b"mcast_join_typed(own IP) [not a group]",
                      sys::mcast_join_typed(mrx as u32, ip), E_INVAL);
            let forged_sock = (sys::ty::SOCKET.raw() as u32) << 26 | 0x1FF;
            expect_eq(b"mcast_join_typed(forged Socket handle) [forged cap]",
                      sys::mcast_join_typed(forged_sock, GROUP), -202);
            expect_eq(b"mcast_join_typed(0) [null handle]", sys::mcast_join_typed(0, GROUP), E_INVAL);

            expect_eq(b"connect_typed() to the group",
                      sys::connect_typed(mtx as u32, &sys::sockaddr_in(GROUP, P_MCAST)), 0);
            let sent = sys::send_typed(mtx as u32, MP);
            expect_true(b"send_typed() to the group: bytes, or -1 for a wire copy with no NIC",
                        sent == MP.len() as isize || sent == -1);

            let mut mbuf = [0u8; 32];
            let mut mgot = -1isize;
            let mut deadline = Deadline::in_ms(5_000);
            while !deadline.expired() {
                mgot = sys::recv_typed(mrx as u32, &mut mbuf);
                if mgot > 0 { break; }
                sys::yield_now();
            }
            expect_eq(b"recv_typed() receives the group datagram (local loopback)",
                      mgot, MP.len() as isize);
            expect_true(b"group payload survives local delivery",
                        mgot > 0 && &mbuf[..mgot as usize] == MP);

            expect_eq(b"mcast_leave_typed()", sys::mcast_leave_typed(mrx as u32, GROUP), 0);
            expect_eq(b"mcast_leave_typed() again [not joined]",
                      sys::mcast_leave_typed(mrx as u32, GROUP), E_INVAL);

            expect_eq(b"close_typed(multicast rx)", sys::close_typed(mrx as u32), 0);
            expect_eq(b"close_typed(multicast tx)", sys::close_typed(mtx as u32), 0);
        }
    }

    sys::close_typed(rx as u32);
    sys::close_typed(tx as u32);
}

/// `wait()` reaps a child that has finished.
///
/// **This could not be checked until 2026-08-30**: `sys_wait` was
/// `pub fn sys_wait() -> i64 { -1 }` and `sys_exit(_code)` discarded the exit
/// code. A parent had no way to learn whether its child finished, or how.
///
/// The `vsbench` harness exposed it while trying to measure a process's full
/// life cycle: it failed with `-2001`, i.e. the start fine and `wait` broken.
///
/// The semantics are `WNOHANG`: it does not block, so this polls with yield.
/// That is deliberate — blocking would require waking the parent from the exit
/// path and touching the scheduler.
fn check_wait_reaps_child() {
    let pid = spawn_child(&[b"exit", b"0"]);
    expect_true(b"spawn a child to exercise wait()", pid > 0);
    if pid <= 0 { return; }

    let mut reaped = -1isize;
    let mut deadline = Deadline::in_ms(20_000);
    while !deadline.expired() {
        reaped = sys::wait();
        if reaped > 0 { break; }
        sys::sleep(1);
    }
    expect_eq(b"wait() returns the exited child TID", reaped, pid);

    // And a second reap must not invent a child.
    expect_err(b"wait() does not repeat an already-reaped child", sys::wait());
}

/// A child that faults is killed ALONE, and its parent's wait says how it
/// died: 128 + the signal Linux would have sent (`crates/core/abi/src/exit_status.rs`).
///
/// Two defects this pins (2026-09-27):
/// * aarch64 HALTED THE MACHINE, motors included, on any EL0 synchronous
///   exception without an arm of its own — an undefined instruction in one
///   user program was a power-off. On that kernel this check never reports:
///   the row sees no summary line at all.
/// * Both ISAs exited fault-killed tasks with status 0, so a parent was told
///   a child that dereferenced NULL had succeeded.
fn check_fault_kills_only_the_child() {
    fn reap(pid: isize) -> (isize, i32) {
        let mut status: i32 = -12345;
        let mut reaped = -1isize;
        let mut deadline = Deadline::in_ms(20_000);
        while !deadline.expired() {
            reaped = sys::wait_status(&mut status as *mut i32);
            if reaped > 0 { break; }
            sys::sleep(1);
        }
        let _ = pid;
        (reaped, status)
    }

    let pid = spawn_child(&[b"fault-udf"]);
    expect_true(b"fault: spawn a child that runs an undefined instruction", pid > 0);
    if pid > 0 {
        let (reaped, status) = reap(pid);
        expect_eq(b"fault: undefined-instruction child reaped, machine alive", reaped, pid);
        expect_eq(b"fault: undefined-instruction status is 128+SIGILL", status as isize, 132);
    }

    let pid = spawn_child(&[b"fault-null"]);
    expect_true(b"fault: spawn a child that writes through NULL", pid > 0);
    if pid > 0 {
        let (reaped, status) = reap(pid);
        expect_eq(b"fault: NULL-write child reaped", reaped, pid);
        expect_eq(b"fault: NULL-write status is 128+SIGSEGV", status as isize, 139);
    }
}

/// Pages the larger measured child grows its break by.
const EXIT_FOOTPRINT_PAGES: usize = 8;

/// Start a child that grows its OWN break by `pages` pages, writes one byte in
/// each, and exits; reap it with `waitpid`. Returns (reaped TID, free pages
/// after - before). The child's pages exist only in its address space and go
/// with it. A break, not a `static`: a bss array would be mapped at load and
/// charged to the row's budget, which the `mem-quota-canary` row measures.
fn touch_exit_reap(pages: usize) -> (isize, isize) {
    let before = sys::meminfo();
    let mut digits = [0u8; 20];
    let pid = spawn_child(&[b"touch", dec(pages as u64, &mut digits), b"0"]);
    if pid <= 0 {
        return (pid, 0);
    }
    let mut status: i32 = -12345;
    let mut got = -1isize;
    let mut deadline = Deadline::in_ms(20_000);
    while !deadline.expired() {
        got = sys::waitpid(pid as u32, &mut status as *mut i32);
        if got > 0 { break; }
        sys::sleep(1);
    }
    // The exit notice follows the child's teardown (wave 11: `note_exit` runs
    // after `release_address_space_at_exit` in `task_exit_with_code`), so the
    // pages are back when `waitpid` returns; `check_exit_storm` asserts that
    // at the instant of the reap. The settle loop stays for what this check
    // measures, the slot-reuse question: 50 x 2 ms is far shorter than "until
    // some later task creation reuses the slot", which never happens inside
    // this loop.
    let mut delta = sys::meminfo() - before;
    let mut looks = 0;
    while delta != 0 && looks < 50 {
        sys::sleep(2);
        delta = sys::meminfo() - before;
        looks += 1;
    }
    (got, delta)
}

/// **A dead child's memory comes back on its own exit** (K-C22(C)): shortly
/// after `waitpid` returns, and with no other task created in between, the
/// free-page count is what it was before the spawn. The address space used
/// to be freed only when a LATER task creation reused the dead child's slot,
/// so the count stayed short by the child's whole address space (tables, its
/// written pages) until then.
///
/// Two measured children with different footprints (8 break pages, then 3), after
/// an unmeasured warm-up that settles the parent's own stack and code pages
/// and what a first spawn of the image keeps for the next: on a kernel that
/// frees at slot reuse, the second spawn's reclaim of the first child (8
/// pages) cannot cancel the second child's hold (3 pages), so at least one
/// delta is non-zero whatever earlier checks left behind.
///
/// **Canary.** Skip the destroy in `release_address_space_at_exit`
/// (`crates/core/sched/src/scheduler.rs`), which leaves every address space to the
/// slot-reuse reclaim: the deltas read -6 and +5 on both ISAs (the second
/// spawn reclaims the first measured child).
fn check_exit_gives_memory_back() {
    let (w, _) = touch_exit_reap(1);
    expect_true(b"exit: warm-up child reaped", w > 0);
    let (a, da) = touch_exit_reap(EXIT_FOOTPRINT_PAGES);
    let (b, db) = touch_exit_reap(3);
    expect_true(b"exit: both measured children reaped", a > 0 && b > 0);
    expect_eq(b"exit: free pages back after reaping an 8-page child (delta)", da, 0);
    expect_eq(b"exit: free pages back after reaping a 3-page child (delta)", db, 0);
}

/// Children the exit storm starts, one at a time, each reaped before the next.
const EXIT_STORM_SPAWNS: usize = 64;

/// One `touch` child that exits with `code`, waited for: `(its TID or the
/// spawn's negative code, what `waitpid` answered, the exit status)`.
fn storm_child(code: i32) -> (isize, isize, i32) {
    let mut digits = [0u8; 20];
    let pid = spawn_child(&[b"touch", b"2", dec(code as u64, &mut digits)]);
    let mut status: i32 = -12345;
    let mut got = -1isize;
    if pid > 0 {
        let mut deadline = Deadline::in_ms(20_000);
        while !deadline.expired() {
            got = sys::waitpid(pid as u32, &mut status as *mut i32);
            if got != -1 { break; }
            sys::sleep(1);
        }
    }
    (pid, got, status)
}

/// **A parent's `waitpid` returns only after its child's teardown** (wave 11,
/// Linux's order: `exit_mm` before `exit_notify`), seen from both ends.
///
/// `EXIT_STORM_SPAWNS` times: start a child that writes two break pages and
/// exits with a code of its own, reap it with `waitpid` (sleeping between
/// looks), and read the free-page count AT ONCE — no settle loop. Around the
/// storm, the kernel's exit-path counters (`DOMAIN_EXIT_STATS`):
///
/// * `exit_teardowns` grows by at least one per child: each released its own
///   address space on its exit path.
/// * `reuse` stays 0: no slot claim found a previous tenant's address space
///   still allocated (the K-C22(B) fallback).
/// * `early` stays 0: no exit notice was published while its task still held
///   its address space.
/// * `short` (reaps after which free pages were still below the pre-spawn
///   count) stays 0: the memory was back when `waitpid` said the child was.
///
/// One line carries all of it, in one write, for the gate row; the same
/// numbers are also checks, so `ALL PASSED` covers them.
///
/// **Canaries** (run by hand): move `note_exit` back above the
/// exit hook in `task_exit_with_code` and `early` counts every child; skip
/// the destroy in `release_address_space_at_exit` and `reuse` (and `short`)
/// are non-zero.
fn check_exit_storm() {
    use sys::{EXIT_STAT_EARLY_NOTICES, EXIT_STAT_EXIT_TEARDOWNS, EXIT_STAT_REUSE_TEARDOWNS};
    let exits0 = sys::exit_stats(EXIT_STAT_EXIT_TEARDOWNS);
    let reuse0 = sys::exit_stats(EXIT_STAT_REUSE_TEARDOWNS);
    let early0 = sys::exit_stats(EXIT_STAT_EARLY_NOTICES);
    expect_true(b"exit storm: DOMAIN_EXIT_STATS answers its three selectors",
                exits0 >= 0 && reuse0 >= 0 && early0 >= 0);
    expect_eq(b"exit storm: DOMAIN_EXIT_STATS(99) -> EINVAL", sys::exit_stats(99), -22);

    // The first child of the image fills what stays resident after it (the
    // image's cached pages): that is not a leak, and it would show as a
    // shortfall on the first sample. One unmeasured child first.
    let _ = storm_child(0);

    let mut spawned = 0usize;
    let mut reaped = 0usize;
    let mut short = 0usize;
    let mut first_short = -1isize;
    for i in 0..EXIT_STORM_SPAWNS {
        let code = (i % 100) as i32;
        let before = sys::meminfo();
        let (pid, got, status) = storm_child(code);
        if pid <= 0 {
            break;
        }
        spawned += 1;
        if sys::meminfo() < before {
            short += 1;
            if first_short < 0 { first_short = i as isize; }
        }
        if got != pid || status != code {
            break;
        }
        reaped += 1;
    }

    let exits = sys::exit_stats(EXIT_STAT_EXIT_TEARDOWNS) - exits0;
    let reuse = sys::exit_stats(EXIT_STAT_REUSE_TEARDOWNS) - reuse0;
    let early = sys::exit_stats(EXIT_STAT_EARLY_NOTICES) - early0;
    out(b"[ABITEST] exit storm: spawns=");
    print_i(spawned as isize);
    out(b" reaped=");
    print_i(reaped as isize);
    out(b" exit_teardowns=+");
    print_i(exits);
    out(b" reuse=");
    print_i(reuse);
    out(b" early=");
    print_i(early);
    out(b" short=");
    print_i(short as isize);
    out(b" first_short=");
    print_i(first_short);
    out(b"\n");
    expect_eq(b"exit storm: every child spawned", spawned as isize, EXIT_STORM_SPAWNS as isize);
    expect_eq(b"exit storm: every child reaped with its own code", reaped as isize,
              EXIT_STORM_SPAWNS as isize);
    expect_true(b"exit storm: each child tore down its own address space",
                exits >= EXIT_STORM_SPAWNS as isize);
    expect_eq(b"exit storm: no slot reused before its teardown (reuse)", reuse, 0);
    expect_eq(b"exit storm: no exit notice ahead of its teardown (early)", early, 0);
    expect_eq(b"exit storm: free pages back when waitpid returns (short)", short as isize, 0);
}

/// Upper bound on the children `check_unreaped_children_are_kept` starts: far
/// above any profile's `MAX_TASKS` it boots under (64 on `qemu`), so a kernel
/// without the admission runs into it instead of a refusal.
const ZOMBIE_SPAWNS_MAX: usize = 512;

/// **An unreaped child's exit notice is kept until the parent reaps it, as a
/// Linux zombie is** (wave 12, EXIT2).
///
/// Start children that exit at once (code `1 + i % 100`) and reap none of
/// them until a spawn is refused. Every notice queued meanwhile holds the
/// place of a task slot, so the refusal comes once the free slots are spoken
/// for; then each child is reaped by name with its own code — none was lost
/// — and a spawn after the reaping works again. `DOMAIN_EXIT_STATS` around
/// it: `drops` (notices that found no room) stays 0, `refusals` grows.
///
/// **Canary** (by hand): make `exit_note::admits` answer `true` — spawns never
/// stop until `ZOMBIE_SPAWNS_MAX`, the table (one entry per task slot) fills
/// with live notices, `drops` counts the overflow, and children that exited
/// are not reaped. Before wave 12 the table held 32 notices and evicted the
/// oldest beyond that.
fn check_unreaped_children_are_kept() {
    use sys::{EXIT_STAT_NOTICE_DROPS, EXIT_STAT_NOTICE_REFUSALS};
    let drops0 = sys::exit_stats(EXIT_STAT_NOTICE_DROPS);
    let refusals0 = sys::exit_stats(EXIT_STAT_NOTICE_REFUSALS);
    let mut kids = [0u32; ZOMBIE_SPAWNS_MAX];
    let mut n = 0usize;
    let mut refused = false;
    while n < ZOMBIE_SPAWNS_MAX {
        let mut code = [0u8; 20];
        let pid = spawn_child(&[b"exit", dec((1 + n % 100) as u64, &mut code)]);
        if pid < 0 {
            refused = true;
            break;
        }
        kids[n] = pid as u32;
        n += 1;
        // Let it exit before the next spawn: the table must fill with
        // notices, not with live children (`/proc/tasks` shows it as `Z`).
        let mut deadline = Deadline::in_ms(5_000);
        while !shared::proc_exited(pid as u32) && !deadline.expired() {
            sys::sleep(1);
        }
    }
    let mut reaped = 0usize;
    for (i, &kid) in kids[..n].iter().enumerate() {
        let mut status: i32 = -12345;
        let mut got = -1isize;
        let mut deadline = Deadline::in_ms(5_000);
        while !deadline.expired() {
            got = sys::waitpid(kid, &mut status as *mut i32);
            if got != -1 { break; }
            sys::sleep(1);
        }
        if got == kid as isize && status == 1 + (i % 100) as i32 {
            reaped += 1;
        }
    }
    let again = spawn_child(&[b"exit", b"0"]);
    let mut again_reaped = false;
    if again > 0 {
        let mut status: i32 = -1;
        let mut deadline = Deadline::in_ms(5_000);
        while !deadline.expired() {
            if sys::waitpid(again as u32, &mut status as *mut i32) == again {
                again_reaped = status == 0;
                break;
            }
            sys::sleep(1);
        }
    }
    let drops = sys::exit_stats(EXIT_STAT_NOTICE_DROPS) - drops0;
    let refusals = sys::exit_stats(EXIT_STAT_NOTICE_REFUSALS) - refusals0;
    out(b"[ABITEST] zombies: spawned=");
    print_i(n as isize);
    out(b" refused=");
    out(if refused { b"yes" } else { b"no" });
    out(b" reaped=");
    print_i(reaped as isize);
    out(b" drops=");
    print_i(drops);
    out(b" refusals=+");
    print_i(refusals);
    out(b"\n");
    expect_true(b"zombies: a spawn is refused while unreaped notices hold the free slots", refused);
    expect_true(b"zombies: the refusal is the notice admission (refusals grew)", refusals >= 1);
    expect_eq(b"zombies: every unreaped child reaped with its own code", reaped as isize, n as isize);
    expect_eq(b"zombies: no exit notice dropped (drops)", drops, 0);
    expect_true(b"zombies: a spawn works again once they are reaped", again_reaped);
}

/// `/proc/<tid>\0` into `buf`; the path's length with its NUL.
fn proc_tid_path(tid: u32, buf: &mut [u8; 20]) -> usize {
    buf[..6].copy_from_slice(b"/proc/");
    let mut digits = [0u8; 10];
    let mut n = 0;
    let mut v = tid;
    loop {
        digits[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 { break; }
    }
    for i in 0..n {
        buf[6 + i] = digits[n - 1 - i];
    }
    buf[6 + n] = 0;
    7 + n
}

/// Wave 12 (owner round 48, Linux `hidepid=2`): an image without the full
/// task view (`Cap<Task>` READ on `"tasks"`; ABITEST.ELF's row holds none)
/// sees in `/proc/tasks` only itself and its descendants — here itself, a
/// child and the child's own child, and nothing else: not its parent, not
/// the idle tasks, not any other row. By path, `/proc/<tid>` opens for
/// itself and a descendant, and a foreign live TID (1, hart 0's idle task)
/// is refused exactly as a TID nobody holds is: it is not even visible.
///
/// Canary: the kernel feature `proc-hidepid-canary` compiles the filter out;
/// every line here goes red but the descendant ones.
fn check_proc_view() {
    let me = sys::getpid() as u32;
    let child = spawn_child(&[b"tree"]);
    expect_true(b"proc view: spawn a child", child > 0);
    if child <= 0 { return; }
    let child = child as u32;

    // Until the grandchild exists: three rows.
    let mut rows = [(0u32, 0u32); 64];
    let mut n = None;
    let mut deadline = Deadline::in_ms(5_000);
    while !deadline.expired() {
        n = proc_task_rows(&mut rows);
        if n.is_none() || n.unwrap_or(0) >= 3 { break; }
        sys::sleep(5);
    }
    let n = n.unwrap_or(0);
    let shown = &rows[..n.min(rows.len())];
    let grandchild = shown.iter().find(|r| r.1 == child).map(|r| r.0).unwrap_or(0);
    out(b"[ABITEST] proc view: rows=");
    print_i(n as isize);
    out(b" self=");
    print_i(me as isize);
    out(b" child=");
    print_i(child as isize);
    out(b" grandchild=");
    print_i(grandchild as isize);
    outln(b"");
    expect_true(b"proc view: /proc/tasks lists itself", shown.iter().any(|r| r.0 == me));
    expect_true(b"proc view: /proc/tasks lists its child", shown.iter().any(|r| r.0 == child && r.1 == me));
    expect_true(b"proc view: /proc/tasks lists its grandchild", grandchild != 0);
    expect_eq(b"proc view: /proc/tasks lists nothing else (hidepid)", n as isize, 3);
    expect_true(b"proc view: no idle task listed", !shown.iter().any(|r| r.0 == 1));

    let mut path = [0u8; 20];
    let l = proc_tid_path(me, &mut path);
    let fd = sys::open_root(&path[..l], 0);
    expect_pos(b"proc view: /proc/<self> opens", fd);
    if fd >= 0 { sys::close(fd as u64); }
    let l = proc_tid_path(child, &mut path);
    let fd = sys::open_root(&path[..l], 0);
    expect_pos(b"proc view: /proc/<child> opens", fd);
    if fd >= 0 { sys::close(fd as u64); }
    let l = proc_tid_path(1, &mut path);
    let foreign = sys::open_root(&path[..l], 0);
    if foreign >= 0 { sys::close(foreign as u64); }
    let l = proc_tid_path(4_000_000_000, &mut path);
    let absent = sys::open_root(&path[..l], 0);
    if absent >= 0 { sys::close(absent as u64); }
    expect_err(b"proc view: /proc/1 (a foreign live TID) does not open", foreign);
    expect_eq(b"proc view: a foreign TID fails as an absent one does", foreign, absent);

    let mut st = 0i32;
    let mut deadline = Deadline::in_ms(20_000);
    let mut got = -1;
    while !deadline.expired() {
        got = sys::waitpid(child, &mut st as *mut i32);
        if got > 0 { break; }
        sys::sleep(5);
    }
    expect_eq(b"proc view: the child is reaped", got, child as isize);
}

// ── Wave 13: native threads ─────────────────────────────────────────────────

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering as AO};

#[repr(C, align(16))]
struct ThreadStack([u8; 16 * 1024]);
static mut T_STACKS: [ThreadStack; 3] = [const { ThreadStack([0; 16 * 1024]) }; 3];

/// The top of thread stack `i` (16-byte aligned).
fn t_stack_top(i: usize) -> usize {
    unsafe { (core::ptr::addr_of_mut!(T_STACKS[i]) as usize) + 16 * 1024 }
}

/// Clear-tid words (a join waits for 0) and the shared state the checks read.
static T_CTID: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
static T_COUNT: AtomicU64 = AtomicU64::new(0);
static T_LOCK: AtomicU32 = AtomicU32::new(0);
static mut T_PLAIN: u64 = 0;
static T_HANDLE: AtomicU32 = AtomicU32::new(0);
static T_READ_OK: AtomicU32 = AtomicU32::new(0);
static T_OPENED: AtomicU32 = AtomicU32::new(0);
static T_GATE: AtomicU32 = AtomicU32::new(0);
static T_TID: AtomicU32 = AtomicU32::new(0);

/// A futex lock: 0 free, 1 held, 2 held with waiters.
fn t_lock() {
    if T_LOCK.compare_exchange(0, 1, AO::Acquire, AO::Relaxed).is_ok() {
        return;
    }
    // Timed: the lock stays correct if a wake goes missing (the
    // `futex-wake-noop-canary` build), so that canary fails only the wake
    // check below instead of hanging the whole run.
    while T_LOCK.swap(2, AO::Acquire) != 0 {
        let _ = sys::futex_wait(&T_LOCK, 2, 50_000_000);
    }
}

fn t_unlock() {
    if T_LOCK.swap(0, AO::Release) == 2 {
        let _ = sys::futex_wake(&T_LOCK, 1);
    }
}

const T_ITERS: u64 = 2000;

/// Contend on the lock with a plain (non-atomic) increment under it, and
/// bump the atomic counter once per iteration.
extern "C" fn t_contend(_z: u64, _stack: u64, _arg: u64) -> ! {
    for _ in 0..T_ITERS {
        t_lock();
        unsafe { T_PLAIN = core::ptr::read_volatile(core::ptr::addr_of!(T_PLAIN)) + 1 };
        t_unlock();
        T_COUNT.fetch_add(1, AO::Relaxed);
    }
    sys::thread_exit(0)
}

/// Use the creator's file handle, open a file of its own for the creator,
/// then wait at the gate until released (so it is alive for the /proc
/// checks).
extern "C" fn t_tables(_z: u64, _stack: u64, _arg: u64) -> ! {
    let mut b = [0u8; 1];
    let h = T_HANDLE.load(AO::Acquire);
    if sys::read(h as u64, &mut b) == 1 {
        T_READ_OK.store(1, AO::Release);
    }
    let f = sys::open_root(sys::cstr!(b"/fat/CONFIG.INI"), 0);
    T_OPENED.store(if f >= 0 { f as u32 } else { 0 }, AO::Release);
    T_TID.store(sys::getpid() as u32, AO::Release);
    let _ = sys::futex_wake(&T_TID, 1);
    while T_GATE.load(AO::Acquire) == 0 {
        let _ = sys::futex_wait(&T_GATE, 0, 0);
    }
    sys::thread_exit(0)
}

static T_WAKE_WORD: AtomicU32 = AtomicU32::new(0);
static T_WAKE_RC: AtomicU64 = AtomicU64::new(0);

/// Wait on `T_WAKE_WORD` for up to 2 s and record how the wait ended.
extern "C" fn t_waiter(_z: u64, _stack: u64, _arg: u64) -> ! {
    let rc = sys::futex_wait(&T_WAKE_WORD, 0, 2_000_000_000);
    T_WAKE_RC.store(rc as i64 as u64, AO::Release);
    sys::thread_exit(0)
}

/// A thread that exits at once.
extern "C" fn t_exit_now(_z: u64, _stack: u64, _arg: u64) -> ! {
    sys::thread_exit(0)
}

/// Rounds of [`check_thread_storm`].
const STORM_ROUNDS: usize = 200;

/// Thread-group exits, many times over, on every hart (CTXHUNT, 2026-10-08).
/// Each round: a child process whose two threads spin on one counter exits 7
/// (its exit must stop them); a thread exits and is joined; a child process
/// whose thread faults while the process exits is reaped.
///
/// Three kernel bugs failed it in about a second on `-smp 4`: the exit path
/// ran `do_schedule` with the hart id it entered on after a wait had moved it
/// (another hart's `current_idx` taken as its own), a Zombie's stack was
/// freed while its hart still ran on it, and the second of two threads
/// breaking one copy-on-write page died (`NotMapped` for an entry the first
/// had just broken). Canaries (gate rows): `exit-stale-hart-canary` and
/// `reap-window-canary` fault or wedge the kernel; `cow-spurious-canary`
/// fails the first check.
fn check_thread_storm() {
    let (mut code_ok, mut joined, mut faulted_reaped) = (0usize, 0usize, 0usize);
    for round in 0..STORM_ROUNDS {
        // The spinners run a millisecond, both bumping one counter, before
        // the exit stops them.
        // What each step saw, for the line a failed round prints: the
        // pid/tid, the reaped pid and status, and the guest ms it took. A
        // deadline that ran out reads ~20000 (reap) or ~5000 (join) here;
        // a wrong status at a short time is the kernel, not the clock.
        let mut seen = [[0isize; 4]; 3];
        let t0 = sys::vdso_uptime_ms();
        let pid = spawn_child(&[b"storm-spin"]);
        if pid > 0 {
            let (got, st) = reap_by_tid(pid);
            if got == pid && st == 7 { code_ok += 1; }
            seen[0] = [pid, got, st as isize, 0];
        }
        let t1 = sys::vdso_uptime_ms();
        seen[0][3] = (t1 - t0) as isize;
        T_CTID[2].store(u32::MAX, AO::Release);
        let t = sys::thread_create(t_exit_now, t_stack_top(2), 0, T_CTID[2].as_ptr());
        let j = t > 0 && t_join(2);
        if j { joined += 1; }
        let t2 = sys::vdso_uptime_ms();
        seen[1] = [t, j as isize, T_CTID[2].load(AO::Acquire) as isize, (t2 - t1) as isize];
        let pid = spawn_child(&[b"storm-fault"]);
        if pid > 0 {
            let (got, st) = reap_by_tid(pid);
            if got == pid { faulted_reaped += 1; }
            seen[2] = [pid, got, st as isize, 0];
        }
        seen[2][3] = (sys::vdso_uptime_ms() - t2) as isize;
        // One failed round answers each check: stop, so a canary that
        // breaks the join (`threads-no-cleartid-canary`) does not wait out
        // every round's deadline.
        if code_ok + joined + faulted_reaped != 3 * (round + 1) {
            out(b"[ABITEST] thread storm: round ");
            print_i(round as isize);
            let names: [&[u8]; 3] = [b" stopped. spin pid=", b" | join tid=", b" | fault pid="];
            let mid: [&[u8]; 3] = [b" got=", b" ok=", b" got="];
            let third: [&[u8]; 3] = [b" st=", b" ctid=", b" st="];
            for k in 0..3 {
                out(names[k]); print_i(seen[k][0]);
                out(mid[k]); print_i(seen[k][1]);
                out(third[k]); print_i(seen[k][2]);
                out(b" ms="); print_i(seen[k][3]);
            }
            out(b"\n");
            break;
        }
    }
    expect_eq(b"thread storm: every spinning child exits with its own code", code_ok as isize,
              STORM_ROUNDS as isize);
    expect_eq(b"thread storm: every thread that exits at once is joined", joined as isize,
              STORM_ROUNDS as isize);
    expect_eq(b"thread storm: every child whose thread faulted is reaped", faulted_reaped as isize,
              STORM_ROUNDS as isize);
}

/// Join: wait until the thread's exit cleared its word, within 5 s.
fn t_join(i: usize) -> bool {
    let mut deadline = Deadline::in_ms(5_000);
    while !deadline.expired() {
        let v = T_CTID[i].load(AO::Acquire);
        if v == 0 {
            return true;
        }
        let _ = sys::futex_wait(&T_CTID[i], v, 100_000_000);
    }
    false
}

/// Native threads (wave 13): two threads and the main thread contend on a
/// futex lock over shared memory; a thread uses the creator's file handle
/// and opens one the creator then uses (one capability table, one
/// descriptor table); `/proc` shows a thread to its own process and hides it
/// from a child process; `exit` from any thread ends the whole process.
///
/// Canaries (gate rows): `threads-private-table-canary` gives a thread its
/// own table, so the handle checks fail; `futex-wake-noop-canary` makes a
/// wake wake nobody, so the joins time out.
fn check_threads() {
    // 1. Contention and join.
    T_COUNT.store(0, AO::Relaxed);
    unsafe { T_PLAIN = 0 };
    let mut tids = [0isize; 2];
    for i in 0..2 {
        T_CTID[i].store(u32::MAX, AO::Release);
        tids[i] = sys::thread_create(t_contend, t_stack_top(i), 0, T_CTID[i].as_ptr());
    }
    expect_true(b"threads: create two threads", tids[0] > 0 && tids[1] > 0 && tids[0] != tids[1]);
    for _ in 0..T_ITERS {
        t_lock();
        unsafe { T_PLAIN = core::ptr::read_volatile(core::ptr::addr_of!(T_PLAIN)) + 1 };
        t_unlock();
    }
    let joined = t_join(0) && t_join(1);
    expect_true(b"threads: both joined through their cleared word", joined);
    expect_eq(b"threads: the atomic count is every thread's", T_COUNT.load(AO::Relaxed) as isize,
              (2 * T_ITERS) as isize);
    expect_eq(b"threads: the futex lock kept the plain count exact",
              unsafe { core::ptr::read_volatile(core::ptr::addr_of!(T_PLAIN)) } as isize, (3 * T_ITERS) as isize);
    // 2. The futex answers.
    let w = AtomicU32::new(5);
    expect_eq(b"threads: futex_wait on a word that differs -> EAGAIN", sys::futex_wait(&w, 6, 0), -11);
    expect_eq(b"threads: futex_wait times out -> ETIMEDOUT", sys::futex_wait(&w, 5, 2_000_000), -110);
    expect_eq(b"threads: futex_wake with no waiter wakes 0", sys::futex_wake(&w, 1), 0);
    // A wake reaches a waiting thread: it returns 0, not its timeout.
    T_WAKE_WORD.store(0, AO::Release);
    T_WAKE_RC.store(u64::MAX, AO::Release);
    T_CTID[0].store(u32::MAX, AO::Release);
    let t = sys::thread_create(t_waiter, t_stack_top(0), 0, T_CTID[0].as_ptr());
    // No sleep stands in for "the waiter is parked". It used to be
    // `sleep(50)`, then a store of 1 and one wake: a waiter that first ran
    // after that read 1, answered EAGAIN, and the wake found nobody (4 boots
    // in 30 of the `vdso-write-window` row under gate load; a new thread
    // first ran 65-84 ms after its creation there). The word now never
    // changes, so a late waiter still parks, and the wake is retried until
    // it finds the waiter queued (it returns 1): the only proof of "parked"
    // ring 3 has.
    let mut woke = 0isize;
    let mut deadline = Deadline::in_ms(5_000);
    while t > 0 && !deadline.expired() {
        woke = sys::futex_wake(&T_WAKE_WORD, 1);
        if woke != 0 {
            break;
        }
        sys::sleep(1);
    }
    let joined = t > 0 && t_join(0);
    let rc = T_WAKE_RC.load(AO::Acquire) as i64 as isize;
    let ok = joined && woke == 1 && rc == 0;
    expect_true(b"threads: futex_wake wakes the waiting thread (it returns 0)", ok);
    if !ok {
        // Which half failed. Not a check: the threads row counts seventeen.
        out(b"[ABITEST]        wake woke=");
        print_i(woke);
        out(b" waiter rc=");
        print_i(rc);
        out(b" joined=");
        print_i(joined as isize);
        out(b"\n");
    }
    // 3. One capability table, one descriptor table.
    let h = sys::open_root(sys::cstr!(b"/fat/CONFIG.INI"), 0);
    expect_true(b"threads: open a file for the thread", h >= 0);
    T_HANDLE.store(if h >= 0 { h as u32 } else { 0 }, AO::Release);
    T_READ_OK.store(0, AO::Relaxed);
    T_OPENED.store(u32::MAX, AO::Relaxed);
    T_GATE.store(0, AO::Relaxed);
    T_TID.store(0, AO::Relaxed);
    T_CTID[2].store(u32::MAX, AO::Release);
    let t = sys::thread_create(t_tables, t_stack_top(2), 0, T_CTID[2].as_ptr());
    expect_true(b"threads: create a thread that uses the tables", t > 0);
    let mut deadline = Deadline::in_ms(20_000);
    while T_TID.load(AO::Acquire) == 0 && !deadline.expired() {
        let _ = sys::futex_wait(&T_TID, 0, 100_000_000);
    }
    expect_eq(b"threads: getpid in a thread is its process's", T_TID.load(AO::Acquire) as isize, sys::getpid());
    expect_true(b"threads: the thread read through the creator's handle", T_READ_OK.load(AO::Acquire) == 1);
    let opened = T_OPENED.load(AO::Acquire);
    let mut b = [0u8; 1];
    expect_true(b"threads: the creator reads through the thread's handle",
                opened != 0 && opened != u32::MAX && sys::read(opened as u64, &mut b) == 1);
    // 4. /proc: the thread is the process's, hidden from a child process.
    let mut path = [0u8; 20];
    let l = proc_tid_path(t.max(0) as u32, &mut path);
    let fd = sys::open_root(&path[..l], 0);
    expect_pos(b"threads: /proc/<thread> opens for its own process", fd);
    if fd >= 0 { sys::close(fd as u64); }
    let pid = spawn_child(&[b"hidden", &path[..l - 1]]);
    if pid > 0 {
        let (got, st) = reap_by_tid(pid);
        expect_true(b"threads: /proc/<thread> is hidden from a child process", got == pid && st == 0);
    }
    T_GATE.store(1, AO::Release);
    let _ = sys::futex_wake(&T_GATE, 1);
    expect_true(b"threads: the table thread joined", t_join(2));
    if opened != 0 && opened != u32::MAX { sys::close(opened as u64); }
    if h >= 0 { sys::close(h as u64); }
    // 5. `exit` from any thread ends the process: a child whose spinning
    // thread would otherwise run forever reports its code.
    let pid = spawn_child(&[b"threads-exit"]);
    if pid > 0 {
        let (got, st) = reap_by_tid(pid);
        expect_true(b"threads: exit ends every thread of the process", got == pid && st == 7);
    }
}

// ── What a thread creates (wave 15) ─────────────────────────────────────────

/// The port handle a thread created for [`check_thread_objects`]
/// (`u32::MAX` until it made one).
static X_PORT: AtomicU32 = AtomicU32::new(u32::MAX);

/// The argument [`x_arg`] received.
static X_ARG: AtomicU64 = AtomicU64::new(0);

/// A thread that records its argument and exits.
extern "C" fn x_arg(_z: u64, _stack: u64, arg: u64) -> ! {
    X_ARG.store(arg, AO::Release);
    sys::thread_exit(0)
}

/// A thread creates a port and exits at once.
extern "C" fn x_make_port(_z: u64, _stack: u64, _arg: u64) -> ! {
    let p = sys::port_create_typed();
    X_PORT.store(if p >= 0 { p as u32 } else { u32::MAX - 1 }, AO::Release);
    sys::thread_exit(0)
}

/// What a thread creates belongs to its process (wave 15, plan 4a): a port a
/// thread made, and then exited, is still the process's. Before, the thread's
/// exit freed it (`port_release_all` of the thread's TID) and the handle in
/// the shared table answered `ECAPSTALE`.
///
/// Canary `thread-objects-canary` (gate row): the port is booked to the
/// thread again, and this check fails.
fn check_thread_objects() {
    const E_EAGAIN: isize = -11;
    X_PORT.store(u32::MAX, AO::Release);
    T_CTID[0].store(u32::MAX, AO::Release);
    let t = sys::thread_create(x_make_port, t_stack_top(0), 0, T_CTID[0].as_ptr());
    let joined = t > 0 && t_join(0);
    let port = X_PORT.load(AO::Acquire);
    let made = joined && port < u32::MAX - 1;
    let mut ev = [0u8; sys::PORT_EVENT_BYTES];
    let rc = if made { sys::port_poll_typed(port, &mut ev) } else { -1 };
    report(b"proc objects: a port a thread made outlives the thread (poll -> EAGAIN)",
           made && rc == E_EAGAIN, rc);
    if made { let _ = sys::port_destroy_typed(port); }
    // A new thread receives the argument `thread_create` was given (wave 15:
    // aarch64 started every thread with its registers zeroed, so it read 0;
    // canary `thread-regs-canary`).
    X_ARG.store(0, AO::Release);
    T_CTID[0].store(u32::MAX, AO::Release);
    let t = sys::thread_create(x_arg, t_stack_top(0), 0x77, T_CTID[0].as_ptr());
    let joined = t > 0 && t_join(0);
    let got = X_ARG.load(AO::Acquire) as i64 as isize;
    report(b"args: a new thread receives its argument (0x77)", joined && got == 0x77, got);
}

/// Code an orphan exits with when it saw itself adopted (`abichild`).
const ORPHAN_ADOPTED: i32 = 0x5A;

/// Wave 13 (orphans, Linux's model): when a task exits, its children go to
/// the nearest live ancestor marked a child subreaper, else to init — this
/// image, the autorun row's task — and they are visible to the adopter in
/// `/proc/tasks` (hidepid view) and reaped by its `waitpid`.
///
/// 1. Init: a child starts a grandchild and exits. The grandchild sees itself
///    adopted by this task; this task lists it as its child, asks it to
///    stop waiting (`task_kill`, a request: its wait ends with `-EINTR`) and reaps it with the code it chose.
/// 2. Subreaper: a child marks itself (`DOMAIN_SUBREAPER`), starts a child
///    that starts a grandchild and exits; the grandchild goes to the marked
///    child, not to init. The marked child exits with a bit per failed step.
///
/// Canary: the kernel feature `orphan-reparent-canary` keeps wave 12's
/// behaviour (no re-link, notices dropped); every adoption line goes red.
fn check_orphans() {
    let me = sys::getpid() as u32;
    expect_eq(b"orphans: the subreaper mark starts clear",
              sys::task_subreaper(sys::SUBREAPER_GET), 0);
    expect_eq(b"orphans: an unknown subreaper op is EINVAL", sys::task_subreaper(9), -22);

    // 1. Init adopts.
    // The orphan stays alive once it saw itself adopted, until this task has
    // listed it and asked it to stop (`abichild`): the release is an event of
    // this task's, not a pause.
    let mut me_dec = [0u8; 20];
    let mid = spawn_child(&[b"orphan-mid", dec(me as u64, &mut me_dec)]);
    expect_true(b"orphans: start the intermediate child", mid > 0);
    if mid <= 0 { return; }
    let (got, st) = reap_by_tid(mid);
    expect_true(b"orphans: the intermediate child exits 0", got == mid && st == 0);
    let (children, last) = children_of(me);
    let orphan = if children == 1 { last } else { 0 };
    out(b"[ABITEST] orphans: init=");
    print_i(me as isize);
    out(b" children=");
    print_i(children as isize);
    out(b" orphan=");
    print_i(orphan as isize);
    outln(b"");
    expect_true(b"orphans: /proc/tasks shows the orphan as init's child", orphan != 0);
    if orphan != 0 {
        expect_true(b"orphans: init asks the listed orphan to stop",
                    sys::task_kill(orphan, sys::KILL_REQUEST, 1, 0) >= 1);
        let (got, st) = reap_by_tid(orphan as isize);
        expect_eq(b"orphans: init reaps the orphan", got, orphan as isize);
        expect_eq(b"orphans: the orphan saw itself adopted by init", st as isize, ORPHAN_ADOPTED as isize);
    }

    // 2. A subreaper adopts, init does not.
    let s = spawn_child(&[b"subreaper"]);
    expect_true(b"orphans: start the subreaper child", s > 0);
    if s <= 0 { return; }
    let (got, st) = reap_by_tid(s);
    expect_eq(b"orphans: the subreaper child is reaped", got, s);
    out(b"[ABITEST] orphans: subreaper failures=");
    print_i(st as isize);
    outln(b"");
    expect_eq(b"orphans: a subreaper adopts and reaps its orphan (failure bits 0)", st as isize, 0);
    expect_eq(b"orphans: init was left no child", children_of(me).0 as isize, 0);
    outln(b"[ABITEST] orphans: done");
}

/// W^X (wave 13, security): a process's store to its own code or read-only
/// data faults (128 + SIGSEGV) and changes nothing. A copy-on-write copy once
/// handed a forked child a private WRITABLE copy that kept the execute bit:
/// writable code (the fork is the Linux personality's now; its row is
/// `lxhello`'s). Canary `cow-ro-canary` (gate row): the stores and the read
/// succeed and these checks fail.
fn check_code_is_read_only() {
    for (what, mode) in [(0u8, &b"store-code"[..]), (1u8, &b"store-rodata"[..])] {
        let pid = spawn_child(&[mode]);
        let (got, st) = if pid > 0 { reap_by_tid(pid) } else { (-1, -1) };
        let ok = got == pid && st == 139;
        if what == 0 {
            expect_true(b"wx: a process's store to its code faults (128+SIGSEGV)", ok);
        } else {
            expect_true(b"wx: a process's store to read-only data faults (128+SIGSEGV)", ok);
        }
    }
    // The kernel writing for the process (a `read` into its code) is refused
    // the same way: `copy_to_user` breaks copy-on-write, and code is no
    // longer copy-on-write.
    let pid = spawn_child(&[b"read-into-code"]);
    let (got, st) = if pid > 0 { reap_by_tid(pid) } else { (-1, -1) };
    expect_true(b"wx: a read() into a process's code is refused", got == pid && st == 0);
}

/// Read-only data is never executable (wave 15, VI). A page two `PT_LOAD`
/// segments shared took the union of their permissions, so the `.rodata`
/// on the last `.text` page ran. The loader now maps each page with its own
/// segment's permissions only (and refuses an image whose segments mapped
/// differently share a page), and `user*.ld` starts `.rodata` on a page of
/// its own. A child process calls a `ret` instruction held in `.rodata`: it
/// dies 128 + SIGSEGV. Canary `rodata-exec-canary` (gate row): read-only
/// segments map read-execute, the call returns and the child exits 0x66.
fn check_rodata_not_executable() {
    let pid = spawn_child(&[b"call-rodata"]);
    let (got, st) = if pid > 0 { reap_by_tid(pid) } else { (-1, -1) };
    out(b"[ABITEST] elfperm: the .rodata call child status=");
    print_i(st as isize);
    outln(b"");
    expect_true(b"elfperm: a call into .rodata faults (128+SIGSEGV)", got == pid && st == 139);
}

/// `mmap`'s `prot` is honoured (wave 13, security): a store to a
/// `PROT_READ` mapping faults (128+SIGSEGV) and a `read()` into it is
/// refused; a `PROT_READ | PROT_WRITE` mapping takes stores; `0` maps
/// nothing (a store faults). Canary `mmap-prot-canary`: every mapping is
/// read-write again and these checks fail.
fn check_mmap_prot() {
    let ro = sys::mmap(0, 4096, sys::PROT_READ, 0, sys::MAP_ANON_FD, 0);
    expect_true(b"mprot: mmap(PROT_READ)", ro > 0);
    if ro <= 0 { return; }
    // The store faults in a child that maps the same protection, as the
    // fault ends the process that makes it.
    let store = |mode: &[u8]| {
        let pid = spawn_child(&[mode]);
        if pid > 0 { reap_by_tid(pid).1 } else { -1 }
    };
    expect_eq(b"mprot: a store to PROT_READ memory faults (128+SIGSEGV)", store(b"mmap-ro") as isize, 139);
    expect_eq(b"mprot: PROT_READ memory reads zero", unsafe { core::ptr::read_volatile(ro as *const u8) } as isize, 0);
    let f = sys::open_root(sys::cstr!(b"/fat/CONFIG.INI"), 0);
    let r = if f >= 0 {
        sys::read(f as u64, unsafe { core::slice::from_raw_parts_mut(ro as *mut u8, 4) })
    } else { 0 };
    if f >= 0 { sys::close(f as u64); }
    expect_true(b"mprot: a read() into PROT_READ memory is refused", f >= 0 && r < 0);
    let rw = sys::mmap(0, 4096, sys::PROT_READ | sys::PROT_WRITE, 0, sys::MAP_ANON_FD, 0);
    let ok = rw > 0 && unsafe {
        core::ptr::write_volatile(rw as *mut u8, 9);
        core::ptr::read_volatile(rw as *const u8) == 9
    };
    expect_true(b"mprot: PROT_READ|PROT_WRITE memory takes stores", ok);
    let none = sys::mmap(0, 4096, 0, 0, sys::MAP_ANON_FD, 0);
    expect_true(b"mprot: mmap(PROT_NONE) reserves", none > 0);
    if none > 0 {
        expect_eq(b"mprot: a store to PROT_NONE memory faults (128+SIGSEGV)", store(b"mmap-none") as isize, 139);
    }
    // Not unmapped: the row stays one call short of a quarter of the
    // filter's room (`seccomp-tests`); the pages go with the task.
}

/// `Errno::ECHILD` — not a child of this task, or already reaped.
const E_CHILD: isize = -10;

/// `waitpid()` reaps ONE named child, and says so three different ways.
///
/// `wait()` and `wait_status()` return the first finished child, so a parent
/// with several learns that *a* child died and never which. The three answers
/// here are the point:
///
///   * the child's TID — reaped, with its code;
///   * `-1` — that child is alive, poll again;
///   * `-ECHILD` — not a child of ours, or already reaped; polling never helps.
///
/// **Two children, and the second is reaped FIRST.** A single-child test
/// passes against an implementation that ignores the TID argument and returns
/// whatever finished — which is exactly the behaviour `waitpid` exists to
/// replace. Reaping out of creation order is what proves the argument is read.
fn check_waitpid_targets_one_child() {
    const CODE_A: i32 = 0x11;
    const CODE_B: i32 = 0x22;

    let a = spawn_child(&[b"exit", b"17"]);
    let b = spawn_child(&[b"exit", b"34"]);
    expect_true(b"spawn two children for waitpid()", a > 0 && b > 0);
    if a <= 0 || b <= 0 { return; }

    // B first, though A was created first.
    let mut status: i32 = -12345;
    let mut got = -1isize;
    let mut deadline = Deadline::in_ms(20_000);
    while !deadline.expired() {
        got = sys::waitpid(b as u32, &mut status as *mut i32);
        if got > 0 { break; }
        sys::sleep(1);
    }
    expect_eq(b"waitpid(B) returns B, not A", got, b);
    expect_eq(b"waitpid(B) reports B's exit code", status as isize, CODE_B as isize);

    // A is still reapable and carries ITS code — proving B's reap did not
    // consume A's notice.
    let mut status_a: i32 = -12345;
    let mut got_a = -1isize;
    let mut deadline = Deadline::in_ms(20_000);
    while !deadline.expired() {
        got_a = sys::waitpid(a as u32, &mut status_a as *mut i32);
        if got_a > 0 { break; }
        sys::sleep(1);
    }
    expect_eq(b"waitpid(A) still returns A afterwards", got_a, a);
    expect_eq(b"waitpid(A) reports A's own exit code", status_a as isize, CODE_A as isize);

    // Reaped once: now indistinguishable from a stranger, which is documented
    // behaviour rather than an accident — nothing keeps a record of dead
    // children for the distinction to be drawn from.
    expect_eq(b"waitpid(B) after reaping -> ECHILD",
              sys::waitpid(b as u32, core::ptr::null_mut()), E_CHILD);
    expect_eq(b"waitpid(stranger) -> ECHILD",
              sys::waitpid(0xFFFF, core::ptr::null_mut()), E_CHILD);
}

/// `wait_status()` reports HOW the child died, not only which one.
///
/// `wait()` returns the TID and discards the exit code the kernel already
/// recorded, so a parent could not tell a clean exit from an abort. On a tree
/// built with `panic = "abort"` that is the difference between "the task
/// finished" and "the task panicked", which is the one thing a supervisor
/// cannot afford to lose.
///
/// **A non-zero code on purpose.** Asserting `0` would pass against a handler
/// that never writes through the pointer at all, since the sentinel would
/// still be whatever the caller initialised it to. 0x5A is written by the
/// child and must come back through the kernel.
fn check_wait_status_reports_the_exit_code() {
    const CODE: i32 = 0x5A;
    let pid = spawn_child(&[b"exit", b"90"]);
    expect_true(b"spawn a child to exercise wait_status()", pid > 0);
    if pid <= 0 { return; }

    // Deliberately NOT the value under test, and not zero: if the kernel
    // never writes, this is what comes back, and it matches neither the
    // expected code nor a plausible default.
    let mut status: i32 = -12345;
    let mut reaped = -1isize;
    let mut deadline = Deadline::in_ms(20_000);
    while !deadline.expired() {
        reaped = sys::wait_status(&mut status as *mut i32);
        if reaped > 0 { break; }
        sys::sleep(1);
    }
    expect_eq(b"wait_status() returns the exited child TID", reaped, pid);
    expect_eq(b"wait_status() reports the child's exit code", status as isize, CODE as isize);

    // A null pointer is the documented way to get `wait()`'s behaviour from
    // this number, and must not fault.
    expect_err(b"wait_status(null) with no children -> -1",
               sys::wait_status(core::ptr::null_mut()));
}

/// `Errno::EACCES` — the answer for a file bound to no image profile.
const E_ACCES: isize = -13;

/// From ring 3: the topology-seeded `Cap<Endpoint>` is REAL.
///
/// This program is granted `endpoint.demo` with `WRITE` by the topology
/// (`crates/core/topology/src/builder.rs`), and `UHELLO.ELF` the same name with
/// `READ`, which is what claims it as the server. Until 2026-09-19 no topology
/// row was named after an image at all, so a spawned process was seeded
/// nothing and this capability could not have existed.
///
/// **What this deliberately does NOT assert, and why.** It does not call
/// `SYS_IPC_FAST_CALL_EP`. The authority refusal and a failed exchange
/// are the SAME value at the ABI — `E_PERM` is `-1` (`dispatch.rs:14`) and the
/// fast-IPC failure path also answers `-1` — so a call with a forged handle
/// and a call with a real one whose server never replies are indistinguishable
/// from here. An assertion over them would pass without proving anything about
/// authority. The property becomes observable from ring 3 only once the happy
/// path works, i.e. once `UHELLO.ELF` accepts and replies; that is a separate
/// change, and the authority check itself is tested directly in
/// `crates/core/ipc/src/endpoint.rs`.
fn check_endpoint_cap() {
    // The seeded handle is not predictable, so find it the way this file
    // already finds a socket cap. `CapTable::lookup` compares
    // `objref::resource_index`, which for a packed kind is the pool INDEX with
    // the generation stripped, so a bounded scan finds it. 32 is
    // `endpoint::MAX_ENDPOINTS`.
    let mut ep = -1isize;
    for i in 0..32u32 {
        let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), i);
        if h >= 0 { ep = h; break; }
    }
    expect_true(b"cap_lookup(Endpoint, ..) finds the topology-seeded cap", ep >= 0);
}

/// The kernel-hosted `entropy` endpoint (wave 9 P9, an endpoint op since D6
/// part A): the call checks the capability first, and a held endpoint either
/// draws from the pool or -- on a boot with no entropy device -- answers
/// `NOT_READY` and writes nothing. Which of the two this boot is, is printed:
/// the gate row that boots this image decides nothing from it, the `entropy:`
/// rows do.
fn check_entropy_read() {
    let mut buf = [0u8; 32];
    expect_eq(b"entropy_read(null handle) reaches no server",
              sys::dev::entropy_read(0, &mut buf).err().map_or(-1, |c| c as isize),
              sys::dev::outcome::NO_SERVER as isize);
    expect_true(b"a refused entropy read writes nothing", buf.iter().all(|b| *b == 0));

    let ep = sys::dev::lookup(sys::dev::key::ENTROPY, 0);
    expect_true(b"lookup(entropy) finds the topology-seeded endpoint", ep.is_some());
    let Some(ep) = ep else { return };
    // A badge the row did not stamp names no capability of this task.
    expect_true(b"lookup(entropy, badge 1) finds nothing", sys::dev::lookup(sys::dev::key::ENTROPY, 1).is_none());
    let r = sys::dev::entropy_read(ep, &mut buf);
    if r == Err(sys::dev::outcome::NOT_READY) {
        outln(b"[ABITEST] entropy pool: unseeded on this boot");
        expect_true(b"entropy_read on an unseeded pool writes nothing", buf.iter().all(|b| *b == 0));
        return;
    }
    outln(b"[ABITEST] entropy pool: seeded on this boot");
    expect_true(b"entropy_read(32) is served", r.is_ok());
    // More than one draw's room: the client loops.
    let mut big = [0u8; 100];
    expect_true(b"entropy_read(100) is served in several draws", sys::dev::entropy_read(ep, &mut big).is_ok());
    expect_true(b"entropy_read(100) is not all zero", big.iter().any(|b| *b != 0));
    let mut again = [0u8; 32];
    expect_true(b"a second entropy read is served", sys::dev::entropy_read(ep, &mut again).is_ok());
    expect_true(b"two entropy reads differ", buf != again);
}

/// `spawn_ex()` starts a process from an image path, under the seccomp profile
/// bound to THAT image's bytes, when the caller holds a launch
/// grant for the image.
///
/// **The child is uhello, for its profile.** UHELLO.ELF's row refuses its
/// probe, the fast IPC call (582); ABITEST.ELF's, which this process runs
/// under, allows it. The filter kills uhello at the probe (exit 159); when the
/// probe is answered, uhello prints `FAILED:` and exits 1. A child that ran
/// under this process's filter, or under none, is therefore reported twice:
/// by its own line and by the exit code reaped here. The probe goes through
/// the native entries' IPC branch (Chain E cut 7), so this is that branch's
/// filter check on every ISA.
///
/// CONFIG.INI is a file the image carries that no profile is bound to, so
/// spawning it is refused with `EACCES` rather than loaded and rejected as a
/// bad ELF. A missing path fails on the read, with something other than
/// `EACCES`.
fn check_spawn() {
    let child = sys::spawn_ex(sys::cstr!(b"/fat/UHELLO.ELF"), None);
    expect_pos(b"spawn_ex(/fat/UHELLO.ELF) returns the child TID", child);
    if child > 0 {
        let mut status: i32 = -12345;
        let mut got = -1isize;
        let mut deadline = Deadline::in_ms(20_000);
        while !deadline.expired() {
            got = sys::waitpid(child as u32, &mut status as *mut i32);
            // -1 is "still running"; anything else is final.
            if got != -1 { break; }
            sys::sleep(1);
        }
        expect_eq(b"waitpid(spawned child) returns its TID", got, child);
        // V1.8 (owner decision, 2026-09-26): a seccomp denial KILLS the task
        // (Linux strict, exit code 128+31 = 159) instead of answering -1.
        expect_eq(
            b"spawned uhello is killed by seccomp (exit 159): its profile refused the fast IPC call",
            status as isize,
            159,
        );
    }

    expect_eq(
        b"spawn_ex(/fat/CONFIG.INI, no image profile) -> EACCES",
        sys::spawn_ex(sys::cstr!(b"/fat/CONFIG.INI"), None),
        E_ACCES,
    );
    // Owner decision 2026-09-28: HELLO.ELF IS bound to an image profile, and
    // the topology has no row named after it, so the kernel refuses it before
    // loading anything (console: `[SPAWN] REFUSED: HELLO.ELF has no topology
    // row`). A bound image is refused with EACCES on no other path.
    expect_eq(
        b"spawn_ex(/fat/HELLO.ELF, bound but no topology row) -> EACCES",
        sys::spawn_ex(sys::cstr!(b"/fat/HELLO.ELF"), None),
        E_ACCES,
    );
    let rc = sys::spawn_ex(sys::cstr!(b"/no/such/binary"), None);
    report(b"spawn_ex(missing path) -> negative, not EACCES", rc < 0 && rc != E_ACCES, rc);
    expect_eq(
        b"spawn_ex(unterminated) -> E_INVAL from libsys",
        sys::spawn_ex(b"/fat/UHELLO.ELF", None),
        sys::E_INVAL,
    );
}

/// The user shell's calls answer wrong arguments as
/// `crates/core/abi/src/syscall_nr.rs` documents. This image's profile lists
/// none of them (only `SH.ELF`'s does): its audit mode lets each through to
/// the dispatcher and records it (`AUDITED_PROBES` in seccomp-tests), so these
/// are the error paths of the real arms, reached from ring 3.
fn check_user_shell_calls_refuse() {
    const EINVAL: isize = -22;
    const ESRCH: isize = -3;
    let me = sys::getpid() as u64;
    // The console's `WAIT` op: `w3` must be 0, refused before any input claim
    // is taken.
    let console = sys::cap_lookup(sys::ty::CONSOLE.raw(), 0);
    expect_true(b"the console handle is held", console > 0);
    // The handle family's query: what the console handle is, without using it.
    match sys::cap_info(console as u32) {
        Ok(i) => {
            expect_eq(b"cap_info(console): the type", i.ty as isize, sys::ty::CONSOLE.raw() as isize);
            expect_eq(b"cap_info(console): READ|WRITE", i.rights as isize, 0b11);
            expect_eq(b"cap_info(console): no expiry", i.expiry_ns as isize, 0);
        }
        Err(e) => expect_eq(b"cap_info(console) answers", e, 0),
    }
    expect_eq(b"cap_info(forged handle) -> ECAPSTALE", sys::cap_info(0).err().unwrap_or(0), -202);
    expect_eq(
        b"console wait(w3=1) -> EINVAL",
        sys::invoke(console as u32, sys::invoke_abi::LOG_CONSOLE_WAIT, [0, 0, 0, 1]).0,
        EINVAL,
    );
    // 611: self, a task that is not a descendant (TID 1, a kernel task), and
    // an unknown `how`.
    expect_eq(b"task_kill(self) -> EINVAL", issue_nr4(9, me, 1, 2, 0), EINVAL);
    expect_eq(b"task_kill(tid 1, not a descendant) -> ESRCH", issue_nr4(9, 1, 1, 2, 0), ESRCH);
    expect_eq(b"task_kill(how=3) -> EINVAL", issue_nr4(9, 1, 3, 2, 0), EINVAL);
    expect_eq(b"task_kill(signo=0) -> EINVAL", issue_nr4(9, 1, 1, 0, 0), EINVAL);
    // 608: a request block of an unknown version, and an image this task holds
    // no launch grant for.
    let mut req = [0u8; 184];
    req[0] = 2; // version 2
    let path = sys::cstr!(b"/fat/REFLEX.ELF");
    expect_eq(
        b"spawn_ex(request version 2) -> EINVAL",
        issue_nr4(5, path.as_ptr() as u64, req.as_ptr() as u64, 0, 0),
        EINVAL,
    );
    expect_eq(
        b"spawn_ex(REFLEX.ELF, no launch grant) -> EACCES",
        issue_nr4(5, path.as_ptr() as u64, 0, 0, 0),
        E_ACCES,
    );
}

// ── The native syscall register contract (Chain E commit 8) ────────────────
//
// crates/core/abi/src/syscall_nr.rs, "Register contract": on return from a
// native syscall ring 3 may rely on the callee-saved registers, sp/gp/tp
// (and their per-ISA equivalents) and the call's outputs; everything else is
// clobbered, and (Kconfig SYSCALL_LEAN_ENTRY) comes back zeroed. One `asm!`
// per ISA saves the callee-saved file, fills it (and the clobbered registers)
// with patterns, issues the call, records what came back and restores the
// file, so nothing but the kernel can touch the registers in between. Run
// over a call answered before the table (getpid), one that switches away
// (yield) and one through the table (cap_info). The second argument register carries `SYSCALL_ABI_CANARY_A1`: a
// kernel built with `syscall-abi-canary` flips a callee-saved bit on the
// native exit for exactly that value, and the `survive` checks go red.

/// Pattern base of the callee-saved registers (register k gets base + k).
const SYSABI_PAT: u64 = 0x5A00;
/// What the clobbered registers are filled with before the call.
const SYSABI_Q: u64 = 0x7E57;

/// The probe's record: `saved` (the caller's own callee-saved file),
/// `after` (that file after the call), `clob` (the clobbered registers after
/// the call). Sizes cover the largest ISA.
#[repr(C)]
struct SysAbiRec {
    saved: [u64; 14],
    after: [u64; 14],
    clob: [u64; 12],
}

/// riscv64: s0-s11, gp, tp and ra (s11 carries the record's address, so its
/// own "pattern" is that address); clobbered t0-t6, a7.
#[cfg(target_arch = "riscv64")]
fn sysabi_probe(nr: u64, a0: u64, a1: u64, r: &mut SysAbiRec) -> isize {
    let rc: isize;
    unsafe {
        core::arch::asm!(
            "sd s0, 0({b})", "sd s1, 8({b})", "sd s2, 16({b})", "sd s3, 24({b})",
            "sd s4, 32({b})", "sd s5, 40({b})", "sd s6, 48({b})", "sd s7, 56({b})",
            "sd s8, 64({b})", "sd s9, 72({b})", "sd s10, 80({b})", "sd s11, 88({b})",
            "sd gp, 96({b})", "sd tp, 104({b})",
            "mv s11, {b}",
            "li s0, {p0}", "li s1, {p1}", "li s2, {p2}", "li s3, {p3}", "li s4, {p4}",
            "li s5, {p5}", "li s6, {p6}", "li s7, {p7}", "li s8, {p8}", "li s9, {p9}",
            "li s10, {p10}", "li gp, {p12}", "li tp, {p13}",
            "li ra, {q}", "li t0, {q}", "li t1, {q}", "li t2, {q}", "li t3, {q}",
            "li t4, {q}", "li t5, {q}", "li t6, {q}",
            "ecall",
            "sd s0, 112(s11)", "sd s1, 120(s11)", "sd s2, 128(s11)", "sd s3, 136(s11)",
            "sd s4, 144(s11)", "sd s5, 152(s11)", "sd s6, 160(s11)", "sd s7, 168(s11)",
            "sd s8, 176(s11)", "sd s9, 184(s11)", "sd s10, 192(s11)", "sd s11, 200(s11)",
            "sd gp, 208(s11)", "sd tp, 216(s11)",
            "sd ra, 224(s11)", "sd t0, 232(s11)", "sd t1, 240(s11)", "sd t2, 248(s11)",
            "sd t3, 256(s11)", "sd t4, 264(s11)", "sd t5, 272(s11)", "sd t6, 280(s11)",
            "sd a7, 288(s11)",
            "mv t0, s11",
            "ld s0, 0(t0)", "ld s1, 8(t0)", "ld s2, 16(t0)", "ld s3, 24(t0)",
            "ld s4, 32(t0)", "ld s5, 40(t0)", "ld s6, 48(t0)", "ld s7, 56(t0)",
            "ld s8, 64(t0)", "ld s9, 72(t0)", "ld s10, 80(t0)", "ld s11, 88(t0)",
            "ld gp, 96(t0)", "ld tp, 104(t0)",
            b = in(reg) r as *mut SysAbiRec,
            p0 = const SYSABI_PAT, p1 = const SYSABI_PAT + 1, p2 = const SYSABI_PAT + 2,
            p3 = const SYSABI_PAT + 3, p4 = const SYSABI_PAT + 4, p5 = const SYSABI_PAT + 5,
            p6 = const SYSABI_PAT + 6, p7 = const SYSABI_PAT + 7, p8 = const SYSABI_PAT + 8,
            p9 = const SYSABI_PAT + 9, p10 = const SYSABI_PAT + 10,
            p12 = const SYSABI_PAT + 12, p13 = const SYSABI_PAT + 13,
            q = const SYSABI_Q,
            in("a7") nr,
            inlateout("a0") a0 as isize => rc,
            in("a1") a1,
            // ra: the probe writes it itself (the kernel keeps it).
            lateout("ra") _,
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
            options(nostack),
        );
    }
    rc
}

/// aarch64: x18-x29 and x30 (x18 is the platform register rustc reserves,
/// which the contract keeps; x28 carries the record's address); clobbered
/// x7-x17.
#[cfg(target_arch = "aarch64")]
fn sysabi_probe(nr: u64, a0: u64, a1: u64, r: &mut SysAbiRec) -> isize {
    let rc: isize;
    unsafe {
        core::arch::asm!(
            "stp x18, x19, [{b}]", "stp x20, x21, [{b}, #16]", "stp x22, x23, [{b}, #32]",
            "stp x24, x25, [{b}, #48]", "stp x26, x27, [{b}, #64]", "stp x28, x29, [{b}, #80]",
            "mov x28, {b}",
            "mov x18, #{p0}", "mov x19, #{p1}", "mov x20, #{p2}", "mov x21, #{p3}",
            "mov x22, #{p4}", "mov x23, #{p5}", "mov x24, #{p6}", "mov x25, #{p7}",
            "mov x26, #{p8}", "mov x27, #{p9}", "mov x29, #{p11}",
            "mov x7, #{q}", "mov x9, #{q}", "mov x10, #{q}", "mov x11, #{q}",
            "mov x12, #{q}", "mov x13, #{q}", "mov x14, #{q}", "mov x15, #{q}",
            "mov x16, #{q}", "mov x17, #{q}", "mov x30, #{q}",
            "svc #0",
            "stp x18, x19, [x28, #112]", "stp x20, x21, [x28, #128]", "stp x22, x23, [x28, #144]",
            "stp x24, x25, [x28, #160]", "stp x26, x27, [x28, #176]", "stp x28, x29, [x28, #192]",
            "stp x7, x8, [x28, #224]", "stp x9, x10, [x28, #240]", "stp x11, x12, [x28, #256]",
            "stp x13, x14, [x28, #272]", "stp x15, x16, [x28, #288]", "stp x17, x30, [x28, #304]",
            "mov x9, x28",
            "ldp x18, x19, [x9]", "ldp x20, x21, [x9, #16]", "ldp x22, x23, [x9, #32]",
            "ldp x24, x25, [x9, #48]", "ldp x26, x27, [x9, #64]", "ldp x28, x29, [x9, #80]",
            b = in(reg) r as *mut SysAbiRec,
            p0 = const SYSABI_PAT, p1 = const SYSABI_PAT + 1, p2 = const SYSABI_PAT + 2,
            p3 = const SYSABI_PAT + 3, p4 = const SYSABI_PAT + 4, p5 = const SYSABI_PAT + 5,
            p6 = const SYSABI_PAT + 6, p7 = const SYSABI_PAT + 7, p8 = const SYSABI_PAT + 8,
            p9 = const SYSABI_PAT + 9, p11 = const SYSABI_PAT + 11,
            q = const SYSABI_Q,
            in("x8") nr,
            inlateout("x0") a0 as isize => rc,
            in("x1") a1,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            // x30: the probe writes it itself (the kernel keeps it).
            lateout("x30") _,
            options(nostack),
        );
    }
    rc
}

/// x86_64: rbx, rbp, r12-r15 (r15 carries the record's address); rcx and
/// r11 are what `sysret` makes them (the return RIP, RFLAGS), not checked.
#[cfg(target_arch = "x86_64")]
fn sysabi_probe(nr: u64, a0: u64, a1: u64, r: &mut SysAbiRec) -> isize {
    let rc: isize;
    unsafe {
        core::arch::asm!(
            "mov [{b}], rbx", "mov [{b} + 8], rbp", "mov [{b} + 16], r12",
            "mov [{b} + 24], r13", "mov [{b} + 32], r14", "mov [{b} + 40], r15",
            "mov r15, {b}",
            "mov rbx, {p0}", "mov rbp, {p1}", "mov r12, {p2}", "mov r13, {p3}", "mov r14, {p4}",
            "syscall",
            "mov [r15 + 112], rbx", "mov [r15 + 120], rbp", "mov [r15 + 128], r12",
            "mov [r15 + 136], r13", "mov [r15 + 144], r14", "mov [r15 + 152], r15",
            "mov rcx, r15",
            "mov rbx, [rcx]", "mov rbp, [rcx + 8]", "mov r12, [rcx + 16]",
            "mov r13, [rcx + 24]", "mov r14, [rcx + 32]", "mov r15, [rcx + 40]",
            b = in(reg) r as *mut SysAbiRec,
            p0 = const SYSABI_PAT, p1 = const SYSABI_PAT + 1, p2 = const SYSABI_PAT + 2,
            p3 = const SYSABI_PAT + 3, p4 = const SYSABI_PAT + 4,
            inlateout("rax") nr as isize => rc,
            in("rdi") a0,
            in("rsi") a1,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    rc
}

/// Did every callee-saved register come back as the probe set it? (The
/// register that carried the record's address must come back as that
/// address.)
fn sysabi_callee_ok(r: &SysAbiRec) -> bool {
    let base = r as *const SysAbiRec as u64;
    #[cfg(target_arch = "riscv64")]
    let want: [u64; 14] = core::array::from_fn(|k| if k == 11 { base } else { SYSABI_PAT + k as u64 });
    #[cfg(target_arch = "aarch64")]
    let want: [u64; 12] = core::array::from_fn(|k| if k == 10 { base } else { SYSABI_PAT + k as u64 });
    #[cfg(target_arch = "x86_64")]
    let want: [u64; 6] = core::array::from_fn(|k| if k == 5 { base } else { SYSABI_PAT + k as u64 });
    // The link register (riscv64 ra, aarch64 x30) is kept too.
    #[cfg(target_arch = "riscv64")]
    let link = r.clob[0] == SYSABI_Q;
    #[cfg(target_arch = "aarch64")]
    let link = r.clob[11] == SYSABI_Q;
    #[cfg(target_arch = "x86_64")]
    let link = true;
    link && want.iter().zip(r.after.iter()).all(|(w, a)| w == a)
}

/// Did every clobbered register come back zeroed (SYSCALL_LEAN_ENTRY) or as
/// the probe set it (the full restore), never anything else, which would be
/// a value the kernel left? The number register: zero or the number.
fn sysabi_clobbered_clean(r: &SysAbiRec, nr: u64) -> bool {
    let ok = |v: u64| v == 0 || v == SYSABI_Q;
    // clob[0] is riscv64's ra, clob[11] aarch64's x30: the link register,
    // which the kernel keeps; `sysabi_callee_ok` checks it.
    #[cfg(target_arch = "riscv64")]
    return r.clob[1..8].iter().all(|&v| ok(v)) && (r.clob[8] == 0 || r.clob[8] == nr);
    #[cfg(target_arch = "aarch64")]
    return ok(r.clob[0]) && (r.clob[1] == 0 || r.clob[1] == nr) && r.clob[2..11].iter().all(|&v| ok(v));
    #[cfg(target_arch = "x86_64")]
    {
        let _ = (r, nr, ok);
        true
    }
}

fn check_syscall_register_contract() {
    // Literal numbers at every call: `tests/host/seccomp-tests` resolves a
    // raw `ecall`'s a7 from its call sites (getpid 10, yield 11, cap_info 1).
    let mut clean = true;
    let mut r = SysAbiRec { saved: [0; 14], after: [0; 14], clob: [0; 12] };
    let rc = sysabi_probe(10, 0, sys::SYSCALL_ABI_CANARY_A1, &mut r);
    report(b"sysabi: callee-saved registers survive getpid (answered before the table)", sysabi_callee_ok(&r), rc);
    clean &= sysabi_clobbered_clean(&r, 10);
    let rc = sysabi_probe(11, 0, sys::SYSCALL_ABI_CANARY_A1, &mut r);
    report(b"sysabi: callee-saved registers survive yield (a switch away and back)", sysabi_callee_ok(&r), rc);
    clean &= sysabi_clobbered_clean(&r, 11);
    let rc = sysabi_probe(1, 0, sys::SYSCALL_ABI_CANARY_A1, &mut r);
    report(b"sysabi: callee-saved registers survive cap_info (through the table)", sysabi_callee_ok(&r), rc);
    clean &= sysabi_clobbered_clean(&r, 1);
    expect_true(b"sysabi: clobbered registers come back zero or as passed, never a kernel value", clean);
}

/// Issue live syscall `nr` raw, for arms whose libsys wrapper cannot pass the
/// argument under test (a null or unmapped pointer, a zero length) or that
/// have no wrapper: four arguments (`a0`..`a3`).
fn issue_nr4(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> isize {
    let ret: isize;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 as isize => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 as isize => ret,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
        // x86_64: rax = number, a0..a3 in rdi rsi rdx r10; `syscall` writes
        // rcx and r11.
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr as isize => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// UDP client and server in **separate processes**.
///
/// **Why this is not the same as the previous test.** That one creates two
/// sockets in one process and sends a datagram to itself. This is the real
/// shape of a service: the server **does not know in advance who will speak to
/// it**, and answers using the return address `recvfrom` gives it.
///
/// If `recvfrom` did not report the sender — as was the case until 2026-08-30
/// — this test could not be written: the server would receive the datagram and
/// have nowhere to answer.
fn check_udp_client_server() {
    let raw = sys::net_getip();
    if raw <= 0 {
        outln(b"[ABITEST] (no IP: client/server not checked)");
        return;
    }
    let ip = (raw as u32).to_be_bytes();
    const P_SRV: u16 = 7401;
    const P_CLI: u16 = 7402;
    const REQUEST: &[u8] = b"ping";
    const REPLY: &[u8] = b"pong";

    // ── SERVER ── (`abichild`'s `udp-server`: binds the port, answers whoever
    // wrote to it)
    let (mut ip_dec, mut port_dec) = ([0u8; 20], [0u8; 20]);
    let pid = spawn_child(&[b"udp-server", dec(raw as u32 as u64, &mut ip_dec), dec(P_SRV as u64, &mut port_dec)]);
    expect_true(b"spawn the UDP server", pid > 0);
    if pid <= 0 { return; }

    // ── CLIENT ──
    let c = sys::socket_typed(2, 2, 0);
    expect_true(b"socket() for the client", c >= 0);
    if c < 0 { return; }
    expect_eq(b"bind() the client", sys::bind_typed(c as u32, &sys::sockaddr_in(ip, P_CLI)), 0);

    let srv_addr = sys::sockaddr_in(ip, P_SRV);
    let mut buf = [0u8; 32];
    let mut from = [0u8; sys::SOCKADDR_LEN];
    let mut got = -1isize;

    // The send is retried: the server may not have reached its `bind` yet. A
    // datagram to an unbound port is dropped, which is correct for UDP — not a
    // failure, but the semantics.
    let mut deadline = Deadline::in_ms(20_000);
    while !deadline.expired() {
        let _ = sys::sendto_typed(c as u32, REQUEST, Some(&srv_addr));
        // Resend every 50 ms of clock (it was every 200 yields, a count).
        let mut resend = Deadline::in_ms(50);
        while !resend.expired() {
            got = sys::recvfrom_typed(c as u32, &mut buf, Some(&mut from));
            if got > 0 { break; }
            sys::yield_now();
        }
        if got > 0 { break; }
    }

    expect_eq(b"the server answers the client", got, REPLY.len() as isize);
    expect_true(
        b"the reply is the expected one",
        got > 0 && &buf[..got as usize] == REPLY,
    );
    // And it comes from the server's port, not just any.
    let port = ((from[2] as u16) << 8) | from[3] as u16;
    expect_eq(b"the reply comes from the server port", port as isize, P_SRV as isize);

    sys::close_typed(c as u32);
    let _ = sys::wait();

    check_socket_release();
    check_fd_quota();
    check_close_names_one_object();
}

/// Can one task take every descriptor on the machine?
///
/// It could. `MAX_FDS` is the size of the kernel's table for the WHOLE
/// machine — sixteen slots — and nothing capped what a single task took of
/// it, so a ring-3 program opening files in a loop denied descriptors to
/// everyone else, the flight recorder's rotation and the ELF loader included.
/// The Kconfig option is even named `MAX_FDS_PER_PROC` and its help text said
/// "Maximum open FDs a single process can hold simultaneously"; it is the
/// table length and always was.
///
/// The ceiling is now `MAX_FDS_PER_TASK` = half the table, mirroring
/// `MAX_SOCKETS_PER_TASK`. This opens past it deliberately: the refusal is the
/// point, and a test that opened only up to the limit would pass against no
/// quota at all.
fn check_fd_quota() {
    const LIMIT: usize = 8;   // MAX_FDS_PER_TASK = MAX_FDS / 2 = 16 / 2
    let mut fds = [-1isize; LIMIT + 2];
    let mut held = 0usize;
    for i in 0..LIMIT + 2 {
        let fd = sys::open_root(sys::cstr!(b"/fat/CONFIG.INI"), 0);
        fds[i] = fd;
        if fd < 0 { break; }
        held += 1;
    }
    expect_eq(b"one task cannot take more than its share of the fd table",
              held as isize, LIMIT as isize);

    // The negative half: the refusal must be the QUOTA, not a table that is
    // simply full or a path that stopped opening. Give one back and the next
    // open must succeed — otherwise this test would pass just as happily
    // against an `open` that had started failing for an unrelated reason.
    if held > 0 {
        expect_eq(b"closing a file returns its slot to the quota",
                  sys::close(fds[0] as u64), 0);
        let again = sys::open_root(sys::cstr!(b"/fat/CONFIG.INI"), 0);
        expect_true(b"after a close, the task may open once more", again >= 0);
        if again >= 0 { sys::close(again as u64); }
        for i in 1..held { sys::close(fds[i] as u64); }
    }
}

/// Does closing a socket actually give the slot back?
///
/// **Why this needed a runtime test and not a review.** A ring-3 program holds
/// two disjoint kinds of object behind one integer: `open` hands out an index
/// into the kernel's descriptor table, `socket` an index into the socket
/// table, and their ranges overlap. `close` routes to the descriptor table
/// only. So `close(a_socket)` used to find a slot that was not in use, return
/// success, and free nothing — and this very file did that five times, in the
/// gate, passing green, while documenting the identical hazard for pipes a few
/// hundred lines above without noticing its own.
///
/// The quota is `MAX_SOCKETS_PER_TASK` = 8. Looping past it is what makes the
/// test discriminate: a leak fails on the ninth iteration, and nothing else
/// about the program changes. Asserting only that the close call returns 0
/// would have passed against the broken version, which is exactly how this
/// survived.
fn check_socket_release() {
    const ROUNDS: usize = 12;   // past the per-task quota of 8
    let mut opened = 0usize;
    for _ in 0..ROUNDS {
        let s = sys::socket_typed(2, 2, 0);   // AF_INET, SOCK_DGRAM
        if s < 0 { break; }
        opened += 1;
        sys::close_typed(s as u32);
    }
    expect_eq(b"a closed socket returns its slot to the quota",
              opened as isize, ROUNDS as isize);

    // And the negative half: `close` is NOT the way to release a socket INDEX.
    // It takes a capability handle, and an index has no kind bits: the kernel
    // reads it as a forged handle and refuses it as stale. The close that
    // follows through the real handle is what tells a refusal from a close: it
    // succeeds only on a socket that is still open.
    let mut s = sys::socket_typed(2, 2, 0);
    let mut idx = if s >= 0 { index_of(sys::ty::SOCKET.raw(), s) } else { -1 };
    // The index is the kernel's, shared by every task, so it may land on 1 or
    // 2, which in this process are OPEN fds (the console, libsys's fd table):
    // `close` would then close the console descriptor and answer 0, and the
    // check below would fail on a collision, not on the property (seen in
    // wave 12, after a phase that left a kernel socket open meanwhile). Hold
    // such a socket and take the next one.
    let mut held = [-1isize; 2];
    let mut n_held = 0;
    while (idx == 1 || idx == 2) && n_held < held.len() {
        held[n_held] = s;
        n_held += 1;
        s = sys::socket_typed(2, 2, 0);
        idx = if s >= 0 { index_of(sys::ty::SOCKET.raw(), s) } else { -1 };
    }
    // `>= 0`, not `expect_pos`: the socket table allocates from index 0, so a
    // perfectly good socket index is 0.
    expect_true(b"socket() for the close-is-not-shutdown check", s >= 0 && idx >= 0);
    if s >= 0 && idx >= 0 {
        // 0..=7 are the process's fd table in libsys,
        // and a closed entry is refused there (`-EBADF`) without a trap; a
        // larger index reaches the kernel as a forged handle. Refused either
        // way, which is what the close below proves.
        let want = if (idx as u64) < sys::FD_TABLE_LEN as u64 { sys::E_BADF } else { E_CAPSTALE };
        expect_eq(b"close(socket index) refused (bad fd or stale handle), not a close",
                  sys::close(idx as u64), want);
        expect_eq(b"close_typed() still closes that socket afterwards",
                  sys::close_typed(s as u32), 0);
    } else if s >= 0 {
        sys::close_typed(s as u32);
    }
    for &h in &held[..n_held] {
        sys::close_typed(h as u32);
    }
}

/// `Errno::ECAPSTALE` — a handle that names nothing live.
const E_CAPSTALE: isize = -202;

/// `Errno::ECAPPERMS` — a live handle without the permission the call needs.
const E_CAPPERMS: isize = -201;

/// A file and a socket behind the same small number, and `close` of the socket
/// leaves the file alone.
///
/// **The hazard.** Descriptors count from 3 and sockets from 0 in two separate
/// tables, so a program routinely holds file N and socket N at once. When
/// libsys's `close` issued the untyped `SYS_CAP_CLOSE`, `close(socket N)` reached
/// the descriptor table and closed file N. `open` and `close` now speak
/// capability handles, whose kind is in the number, so the kernel releases
/// the object the handle names.
///
/// The collision is constructed, not assumed: sockets first, then files until
/// one lands on an index a socket holds, both found with `cap_lookup`. Both
/// tables hand out their lowest free slot, but they are shared with every
/// other task, so a boot in which no index is shared says so on its own line
/// instead of passing checks it never ran.
fn check_close_names_one_object() {
    const SOCKETS: usize = 8; // MAX_SOCKETS_PER_TASK
    const FILES: usize = 4;
    let mut buf = [0u8; 16];

    let mut socks = [(-1isize, -1isize); SOCKETS]; // (handle, socket index)
    for slot in socks.iter_mut() {
        let s = sys::socket_typed(2, 2, 0);
        if s < 0 {
            break;
        }
        *slot = (s, index_of(sys::ty::SOCKET.raw(), s));
    }
    let mut files = [-1isize; FILES];
    let mut pair = (-1isize, -1isize, -1isize); // (file, socket, shared index)
    for f in files.iter_mut() {
        let h = sys::open_root(sys::cstr!(b"/fat/CONFIG.INI"), 0);
        if h < 0 {
            break;
        }
        *f = h;
        let n = index_of(sys::ty::FILE.raw(), h);
        if let Some(&(s, _)) = socks.iter().find(|&&(s, i)| s >= 0 && i == n) {
            pair = (h, s, n);
            break;
        }
    }
    report(b"open() returns a Cap<File> handle", files[0] >= 0, files[0]);

    let (file, sock, n) = pair;
    if file < 0 {
        outln(b"[ABITEST] (no file and socket share an index: close collision not constructed)");
    } else {
        out(b"[ABITEST]        file and socket share index ");
        print_i(n);
        out(b"\n");
        expect_true(b"the two handles differ where the indices collide", sock != file);
        expect_eq(b"close(socket at index n) -> 0", sys::close(sock as u64), 0);
        let got = sys::read(file as u64, &mut buf);
        report(b"the file at index n still reads after close(socket)", got > 0, got);
        expect_eq(b"cap_lookup(File, n) still names the file",
                  sys::cap_lookup(sys::ty::FILE.raw(), n as u32), file);
        expect_eq(b"close(socket) again -> ECAPSTALE (it was the socket that closed)",
                  sys::close(sock as u64), E_CAPSTALE);
        expect_eq(b"write() to a READ-only file handle -> ECAPPERMS",
                  sys::write(file as u64, b"x"), E_CAPPERMS);
    }

    for &(s, _) in socks.iter() {
        if s >= 0 && s != sock {
            sys::close(s as u64);
        }
    }
    for &f in files.iter() {
        if f >= 0 && f != file {
            sys::close(f as u64);
        }
    }
    if file >= 0 {
        expect_eq(b"close(file) -> 0", sys::close(file as u64), 0);
        expect_eq(b"read() after close(file) -> ECAPSTALE",
                  sys::read(file as u64, &mut buf), E_CAPSTALE);
    }
}

/// The table index behind a capability handle of `kind`, or -1.
fn index_of(kind: u8, handle: isize) -> isize {
    for i in 0..32u32 {
        if sys::cap_lookup(kind, i) == handle {
            return i as isize;
        }
    }
    -1
}

/// The `Motor` interface's `estop` is a REAL safety path, and this is the ABI
/// half of that claim.
///
/// **Destructive on purpose, so it runs last** — see `_start`. The call
/// latches the machine's e-stop, and the latch is not cleared by the call
/// returning, by the emergency going away, or by the program exiting: only an
/// operator `MODE_ID_ESTOP_RESET` clears it. Every motor write for the rest of
/// this boot is therefore clamped to zero. That is the correct behaviour, and
/// it is precisely why no other check may follow.
///
/// Autorun seeds this program with both motors RW (`motor.0` and `motor.1`,
/// `crates/core/topology/src/builder.rs`), and the rule is that stopping never demands
/// more authority than driving — so a caller that can drive a wheel gets 0
/// here. A program holding no motor would get `-EPERM` instead; that arm has
/// no ring-3 caller in the gate today and is asserted only by argument.
///
/// What this does NOT check is that the stop HELD: that is the job of the
/// `userspace: ring-3 e-stop` scenario, which drives the wheels, latches, and
/// then keeps asking for 60% and requires every ask to come back at duty 0.
/// Here the claim is narrower and about the ABI alone: the call reaches a
/// handler and reports success, instead of the -1 it returned for as long as
/// `dispatch` swallowed it.
fn check_estop_is_a_real_safety_path() {
    // Register form, as the safety path is reached from the control loop.
    let served = match sys::dev::lookup(sys::dev::key::MOTOR, 0) {
        Some(ep) => sys::dev::succeeded(MotorClient::new(Regs(ep)).estop()),
        None => false,
    };
    expect_eq(b"robot_estop() IS implemented (latches; must run last)",
              served as isize, 1);
}

fn check_kernel_stubs() {
    // The robot-control and platform-info stubs are gone (D6): there is no
    // call to assert a refusal of, and mount, umount and sync went with them
    // (a ring-3 mount was always refused, sync reported success without
    // flushing). What remains is `stat` and `taskinfo`.
    //
    // `stat` is implemented (it was a `-1` stub asserted
    // here as one): the root is a directory.
    let mut statbuf = [0u8; 64];
    expect_eq(b"stat(/) -> 0", sys::stat(sys::cstr!(b"/"), &mut statbuf), 0);
    let mode = u32::from_le_bytes([statbuf[8], statbuf[9], statbuf[10], statbuf[11]]);
    expect_eq(b"stat(/) is a directory", (mode & 0o170000) as isize, 0o040000);
    expect_err(b"stat(missing) -> negative", sys::stat(sys::cstr!(b"/no/such"), &mut statbuf));

    // sys_taskinfo is `{ 0 }` too — it reports nothing but is not an error.
    // `taskinfo` was a stub returning 0 with an untouched buffer; it reports
    // the calling task since 2026-09-11. The tid check is what makes this
    // discriminate: a handler that writes the right BYTE COUNT and garbage
    // passes a length assertion and fails this one.
    {
        let mut ti = [0u8; sys::TASKINFO_BYTES];
        expect_eq(b"taskinfo() -> TASKINFO_BYTES",
                  sys::taskinfo(&mut ti), sys::TASKINFO_BYTES as isize);
        let tid = u64::from_le_bytes([ti[0], ti[1], ti[2], ti[3],
                                      ti[4], ti[5], ti[6], ti[7]]);
        expect_eq(b"taskinfo() reports OUR tid", tid as isize, sys::getpid());
        expect_err(b"taskinfo() refuses a short buffer",
                   sys::taskinfo(&mut ti[..sys::TASKINFO_BYTES - 1]));
    }
}

// ── Syscall numbers with a wrapper but no dispatch arm ──────────────────────

fn check_missing_dispatch_arms() {
    // An unclaimed syscall number falls through to the default arm: the ABI
    // has a defined answer for a number it does not know.
    expect_err(b"unknown syscall number -> -1", unknown_syscall());
}

/// Issue a syscall number no arm claims (999 is above every number in
/// `crates/core/syscall/src/numbers.rs`). Kept local because libsys deliberately
/// exposes no raw-ecall escape hatch.
fn unknown_syscall() -> isize {
    let ret: isize;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!(
            "ecall",
            in("a7") 999u64,
            lateout("a0") ret,
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
            options(nostack),
        );
        // aarch64 twin (phase 6 prep — no kernel dispatch to answer this
        // yet; see `crates/core/abi/src/syscall_nr.rs`'s "Register convention").
        // x8 mirrors a7.
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "svc #0",
            in("x8") 999u64,
            lateout("x0") ret,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "syscall",
            inlateout("rax") 999isize => ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

// ── Dispatch arms written inline in `dispatch.rs` ──────────────────────────
//
// These arms have no handler function, so `tests/host/syscall-tests` (which
// compiles `handlers.rs`, not `dispatch.rs`) cannot reach them on the host;
// this is their only test. Each row is a refusal chosen so that the arm
// WITHOUT its check would answer something other than the refusal: a physical
// address, 0, or a bind result.
fn check_inline_dispatch_arms_refuse() {
    // No `Cap<Irq>`: acknowledging or binding an interrupt is refused before
    // the interrupt controller or the bind table is touched (0 / a CPU
    // otherwise). The handle carries the line's type in its top six bits
    // (`CapHandle::KIND_SHIFT` = 26) and names a slot this image never granted.
    let forged_irq = (sys::ty::IRQ.raw() as u32) << 26 | 0x1FF;
    expect_eq(b"irq_ack(forged Irq handle) -> ECAPSTALE", sys::irq_ack(forged_irq), -202);
    expect_eq(b"irq_bind(forged Irq handle) -> ECAPSTALE",
              sys::irq_bind(forged_irq, 0, 0, sys::DEVICE_IRQ_CPU_ANY), -202);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // `panic = "abort"` + `overflow-checks = true`: any panic is a board
    // reset, so this must not itself allocate, format, or arithmetic.
    outln(b"[ABITEST] PANIC");
    sys::exit(2);
}

// ── The foreign-ABI family (D6, `azos_abi::foreign`) ─────────────────────────
//
// A child process (`abichild`'s `foreign` mode) registers a trap entry and
// resumes into a tiny "foreign program" (assembly, on a stack of its own)
// that makes three traps. Each trap must be reflected to the entry, with the
// program's registers in the frame; the entry answers and resumes. The
// program keeps a value in one register the whole time and uses the first
// answer in the second trap, so a register lost by the reflect or by the
// resume shows. The child exits 0 when the whole conversation held, else with
// the number of the step that did not.

fn check_foreign_abi() {
    let pid = spawn_child(&[b"foreign"]);
    expect_true(b"foreign: spawn the probe child", pid > 0);
    if pid <= 0 {
        return;
    }
    let (reaped, status) = reap_by_tid(pid);
    expect_eq(b"foreign: the probe child is reaped", reaped, pid);
    // 10 is the registration refused: a kernel without the personality
    // machinery answers -ENOSYS, and there is nothing to check then.
    if status == 10 {
        return;
    }
    expect_eq(b"foreign: three traps reflected, answered and resumed", status as isize, 0);
}

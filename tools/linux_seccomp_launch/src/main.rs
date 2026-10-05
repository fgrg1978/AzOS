// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! PID 1 of the Linux+seccomp column of vsbench.
//!
//! The initramfs holds two files: this launcher as `/init` and the unchanged
//! vsbench Linux ELF as `/vsbench`. The launcher
//!
//!  1. sets `PR_SET_NO_NEW_PRIVS`,
//!  2. installs the allow-list of `allow.rs` as a seccomp-bpf filter
//!     (`bpf.rs`), default `SECCOMP_RET_KILL_PROCESS`,
//!  3. `execve`s `/vsbench` with its own `argv` (argv[0] replaced by
//!     `/vsbench`) and `envp`.
//!
//! A seccomp filter survives `execve` and is inherited by every `clone`, so
//! vsbench and all the peers it forks run under it, and vsbench's source is
//! not touched (the AzOS profile scanner reads that source).
//!
//! **`PR_SET_NO_NEW_PRIVS` although PID 1 is root.** Installing a filter needs
//! either that bit or `CAP_SYS_ADMIN`. PID 1 of an initramfs has the
//! capability today, but setting the bit makes the install independent of the
//! capability set the guest happens to boot with. For a static, non-setuid ELF
//! it changes nothing about the `execve`.
//!
//! Same conventions as vsbench's Linux side: raw `ecall`, no libc, no heap,
//! output on fd 2. Every line starts with `[VSBENCH-SECCOMP]`, which the
//! compare script's lane parser (`[VSBENCH] linux `) does not match.
//!
//! **Canary.** A kernel command-line parameter `VSBENCH_SECCOMP_CANARY=1`
//! reaches `/init` as an environment variable. With it, the launcher calls
//! `getppid` (173, not in the list) after installing the filter, and the
//! process must die by SIGSYS before printing anything else.

#![no_std]
#![no_main]

// `Syscall::name` and `VDSO_FALLBACKS` are read by host-tests, not here.
#[allow(dead_code)]
mod allow;
mod bpf;

const LINUX_SYS_WRITE: usize = 64;
const LINUX_SYS_EXIT: usize = 93;
const LINUX_SYS_PRCTL: usize = 167;
const LINUX_SYS_GETPPID: usize = 173;
const LINUX_SYS_EXECVE: usize = 221;
const LINUX_SYS_SECCOMP: usize = 277;

const PR_SET_NO_NEW_PRIVS: usize = 38;
const SECCOMP_SET_MODE_FILTER: usize = 1;

static PROGRAM: [bpf::SockFilter; bpf::LEN] = bpf::program();

const TARGET: &[u8] = b"/vsbench\0";
const CANARY_ENV: &[u8] = b"VSBENCH_SECCOMP_CANARY=1";

#[inline(always)]
unsafe fn ecall(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            options(nostack),
        );
    }
    ret
}

fn say(bytes: &[u8]) {
    unsafe { ecall(LINUX_SYS_WRITE, 2, bytes.as_ptr() as usize, bytes.len(), 0, 0) };
}

fn say_num(n: isize) {
    let mut buf = [0u8; 24];
    let mut i = buf.len();
    let neg = n < 0;
    let mut u = n.unsigned_abs();
    loop {
        i -= 1;
        buf[i] = b'0' + (u % 10) as u8;
        u /= 10;
        if u == 0 { break; }
    }
    if neg {
        i -= 1;
        buf[i] = b'-';
    }
    say(&buf[i..]);
}

fn exit(code: usize) -> ! {
    unsafe { ecall(LINUX_SYS_EXIT, code, 0, 0, 0, 0) };
    loop {}
}

fn fail(step: &[u8], rc: isize, code: usize) -> ! {
    say(b"[VSBENCH-SECCOMP] launcher FAIL: ");
    say(step);
    say(b" rc=");
    say_num(rc);
    say(b"\n");
    exit(code)
}

/// Is `want` one of the NUL-terminated strings of the NULL-terminated array?
unsafe fn env_has(envp: *const *const u8, want: &[u8]) -> bool {
    let mut e = envp;
    unsafe {
        while !(*e).is_null() {
            let s = *e;
            let mut i = 0;
            while i < want.len() && *s.add(i) == want[i] {
                i += 1;
            }
            if i == want.len() && *s.add(i) == 0 {
                return true;
            }
            e = e.add(1);
        }
    }
    false
}

/// Naked for the same reason as vsbench's: the first instruction must see the
/// `sp` the kernel handed over, which points at `argc`, `argv[]`, `envp[]`.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!("mv a0, sp", "j {0}", sym launch)
}

extern "C" fn launch(sp: usize) -> ! {
    let argc = unsafe { core::ptr::read(sp as *const usize) };
    let argv = (sp + 8) as *const *const u8;
    let envp = (sp + 8 + argc * 8 + 8) as *const *const u8;
    let canary = unsafe { env_has(envp, CANARY_ENV) };

    let vsbench = allow::ALLOWED.iter().filter(|s| s.by == allow::By::Vsbench).count();
    say(b"[VSBENCH-SECCOMP] launcher: allow-list ");
    say_num(allow::ALLOWED.len() as isize);
    say(b" syscalls (");
    say_num(vsbench as isize);
    say(b" vsbench, the launcher's execve among them), BPF ");
    say_num(bpf::LEN as isize);
    say(b" instructions, default KILL_PROCESS\n");

    let rc = unsafe { ecall(LINUX_SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        fail(b"prctl(PR_SET_NO_NEW_PRIVS)", rc, 2);
    }

    let fprog = bpf::SockFprog { len: bpf::LEN as u16, filter: PROGRAM.as_ptr() };
    let rc = unsafe {
        ecall(LINUX_SYS_SECCOMP, SECCOMP_SET_MODE_FILTER, 0,
              &fprog as *const bpf::SockFprog as usize, 0, 0)
    };
    if rc != 0 {
        // Without the filter there is no column: never exec vsbench unfiltered
        // under the filtered label.
        fail(b"seccomp(SECCOMP_SET_MODE_FILTER)", rc, 2);
    }
    say(b"[VSBENCH-SECCOMP] filter installed; execve /vsbench\n");

    if canary {
        say(b"[VSBENCH-SECCOMP] canary: calling getppid (173), outside the allow-list; SIGSYS must kill this process now\n");
        let rc = unsafe { ecall(LINUX_SYS_GETPPID, 0, 0, 0, 0, 0) };
        fail(b"canary getppid returned; the filter did not kill", rc, 3);
    }

    // vsbench's argv[0] is the program it runs as: `/vsbench`, not this
    // launcher's `/init`. vsbench reads it to start itself again (its
    // `spawn+wait` lane, wave 12); handed `/init`, that child would re-run
    // this launcher, whose `prctl`/`seccomp` the filter kills. The rest of
    // the argv is passed on unchanged.
    let mut child_argv = [0usize; 16];
    child_argv[0] = TARGET.as_ptr() as usize;
    let mut n = 1;
    while n < argc && n < child_argv.len() - 1 {
        child_argv[n] = unsafe { core::ptr::read(argv.add(n)) } as usize;
        n += 1;
    }
    let rc = unsafe {
        ecall(LINUX_SYS_EXECVE, TARGET.as_ptr() as usize, child_argv.as_ptr() as usize,
              envp as usize, 0, 0)
    };
    fail(b"execve(/vsbench)", rc, 2)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(4)
}

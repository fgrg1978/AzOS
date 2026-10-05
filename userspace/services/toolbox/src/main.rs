// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `TOOLBOX.ELF`: the user shell's multicall tool image (RFC-0055 §5.7),
//! dispatched on `argv[0]`.
//!
//! It holds no capability of its own (its topology row grants none): it reads
//! and writes the fds the shell moved to it (`SYS_SPAWN_EX`), the console,
//! and files it opens read-only. A stop request ends its waits with `-EINTR`;
//! it then exits 130.
//!
//! Applets: `args` (prints argv, the environment and the working directory),
//! `cat`, `echo`, `false`, `ls`, `sleep`, `spin` (computes forever without a
//! syscall), `true`, `wc`, `yes`.

#![no_std]
#![no_main]

use azos_libsys as sys;

const PATH_MAX: usize = 128;

fn put(fd: u64, b: &[u8]) -> isize {
    let mut done = 0usize;
    while done < b.len() {
        let r = sys::write(fd, &b[done..]);
        if r <= 0 {
            return r;
        }
        done += r as usize;
    }
    done as isize
}

fn put_num(fd: u64, mut v: u64) {
    let mut d = [0u8; 20];
    let mut i = d.len();
    loop {
        i -= 1;
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let _ = put(fd, &d[i..]);
}

/// `v` in decimal at the start of `out`; the digits written (at most 20).
fn fmt_num(mut v: u64, out: &mut [u8]) -> usize {
    let mut d = [0u8; 20];
    let mut i = d.len();
    loop {
        i -= 1;
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let n = d.len() - i;
    out[..n].copy_from_slice(&d[i..]);
    n
}

fn fail(what: &[u8], why: &[u8]) {
    let _ = put(2, what);
    let _ = put(2, b": ");
    let _ = put(2, why);
    let _ = put(2, b"\n");
}

/// `p` made absolute against the working directory, NUL-terminated.
fn absolute(p: &[u8], out: &mut [u8; PATH_MAX + 1]) -> Option<usize> {
    let mut n = 0usize;
    let mut push = |part: &[u8], n: &mut usize| -> Option<()> {
        for comp in part.split(|&b| b == b'/') {
            match comp {
                b"" | b"." => {}
                b".." => {
                    while *n > 0 && out[*n - 1] != b'/' {
                        *n -= 1;
                    }
                    *n = n.saturating_sub(1);
                }
                c => {
                    if *n + 1 + c.len() > PATH_MAX {
                        return None;
                    }
                    out[*n] = b'/';
                    out[*n + 1..*n + 1 + c.len()].copy_from_slice(c);
                    *n += 1 + c.len();
                }
            }
        }
        Some(())
    };
    if p.first() != Some(&b'/') {
        push(sys::cwd(), &mut n)?;
    }
    push(p, &mut n)?;
    if n == 0 {
        out[0] = b'/';
        n = 1;
    }
    out[n] = 0;
    Some(n)
}

/// Copy `from` to fd 1. Returns an exit code.
fn copy_to_stdout(from: u64) -> i32 {
    let mut b = [0u8; 1024];
    loop {
        let r = sys::read(from, &mut b);
        if r == 0 {
            return 0;
        }
        if r == sys::E_INTR {
            return 130;
        }
        if r < 0 {
            return 1;
        }
        let w = put(1, &b[..r as usize]);
        if w == sys::E_PIPE {
            return 0;
        }
        if w < 0 {
            return if w == sys::E_INTR { 130 } else { 1 };
        }
    }
}

/// `ps` (wave 12): the kernel's task list, `/proc/tasks` (procfs, mounted
/// read-only at `/proc`): TID, parent, priority, state, name.
fn ps() -> i32 {
    if sys::argc() > 1 {
        fail(b"ps", b"takes no arguments");
        return 2;
    }
    let h = sys::open(b"/proc/tasks\0", 0);
    if h < 0 {
        fail(b"ps", b"cannot open /proc/tasks");
        return 1;
    }
    let mut b = [0u8; 1024];
    let mut st = 0;
    loop {
        let r = sys::file_read_typed(h as u32, &mut b);
        if r < 0 {
            fail(b"ps", b"read failed");
            st = 1;
            break;
        }
        if r == 0 || put(1, &b[..r as usize]) < 0 {
            break;
        }
    }
    let _ = sys::close_typed(h as u32);
    st
}

fn cat() -> i32 {
    if sys::argc() < 2 {
        return copy_to_stdout(0);
    }
    let mut st = 0;
    for i in 1..sys::argc() {
        let a = sys::arg(i).unwrap_or(b"");
        let mut p = [0u8; PATH_MAX + 1];
        let Some(n) = absolute(a, &mut p) else {
            fail(a, b"path too long");
            st = 1;
            continue;
        };
        let h = sys::open(&p[..n + 1], 0);
        if h < 0 {
            fail(a, b"no such file");
            st = 1;
            continue;
        }
        let mut b = [0u8; 1024];
        loop {
            let r = sys::file_read_typed(h as u32, &mut b);
            if r <= 0 {
                break;
            }
            if put(1, &b[..r as usize]) < 0 {
                break;
            }
        }
        let _ = sys::close_typed(h as u32);
    }
    st
}

fn echo() -> i32 {
    let mut line = [0u8; 1024];
    let mut n = 0;
    for i in 1..sys::argc() {
        let a = sys::arg(i).unwrap_or(b"");
        if i > 1 && n < line.len() {
            line[n] = b' ';
            n += 1;
        }
        let k = a.len().min(line.len() - n);
        line[n..n + k].copy_from_slice(&a[..k]);
        n += k;
    }
    if n < line.len() {
        line[n] = b'\n';
        n += 1;
    }
    if put(1, &line[..n]) < 0 { 1 } else { 0 }
}

fn ls() -> i32 {
    let target = if sys::argc() > 1 { sys::arg(1).unwrap_or(b".") } else { b"." };
    let mut p = [0u8; PATH_MAX + 1];
    let Some(n) = absolute(target, &mut p) else { return 1 };
    let mut idx = 0u64;
    loop {
        let mut nm = [0u8; sys::READDIR_NAME_BYTES];
        let (mut size, mut isdir) = (0u32, 0u32);
        if sys::readdir(&p[..n + 1], idx, &mut nm, &mut size, &mut isdir) != 0 {
            break;
        }
        let l = nm.iter().position(|&b| b == 0).unwrap_or(nm.len());
        let mut line = [0u8; sys::READDIR_NAME_BYTES + 2];
        line[..l].copy_from_slice(&nm[..l]);
        let mut k = l;
        if isdir != 0 {
            line[k] = b'/';
            k += 1;
        }
        line[k] = b'\n';
        if put(1, &line[..k + 1]) < 0 {
            return 1;
        }
        idx += 1;
    }
    if idx == 0 {
        fail(target, b"empty or no such directory");
        return 1;
    }
    0
}

fn wc() -> i32 {
    let (mut lines, mut words, mut bytes) = (0u64, 0u64, 0u64);
    let mut in_word = false;
    let mut b = [0u8; 1024];
    loop {
        let r = sys::read(0, &mut b);
        if r == sys::E_INTR {
            return 130;
        }
        if r <= 0 {
            break;
        }
        for &c in &b[..r as usize] {
            bytes += 1;
            if c == b'\n' {
                lines += 1;
            }
            if c == b' ' || c == b'\n' || c == b'\t' {
                in_word = false;
            } else if !in_word {
                in_word = true;
                words += 1;
            }
        }
    }
    // One write for the whole line: the console keeps a ring-3 write whole
    // (a kernel line is deferred while it lasts), not a line made of six. On
    // aarch64 a reap marker landed between `1 2 ` and `8` (gate row
    // `sh: pipeline`).
    let mut line = [0u8; 64];
    let mut n = 0usize;
    for (i, v) in [lines, words, bytes].into_iter().enumerate() {
        if i > 0 {
            line[n] = b' ';
            n += 1;
        }
        n += fmt_num(v, &mut line[n..]);
    }
    line[n] = b'\n';
    let _ = put(1, &line[..n + 1]);
    0
}

fn args() -> i32 {
    let _ = put(1, b"argc=");
    put_num(1, sys::argc() as u64);
    let _ = put(1, b"\n");
    for i in 0..sys::argc() {
        let _ = put(1, b"argv[");
        put_num(1, i as u64);
        let _ = put(1, b"]=");
        let _ = put(1, sys::arg(i).unwrap_or(b""));
        let _ = put(1, b"\n");
    }
    let mut i = 0;
    while let Some(kv) = sys::env_at(i) {
        let _ = put(1, b"env ");
        let _ = put(1, kv);
        let _ = put(1, b"\n");
        i += 1;
    }
    let _ = put(1, b"cwd=");
    let _ = put(1, sys::cwd());
    let _ = put(1, b"\n");
    0
}

fn yes() -> i32 {
    let word = if sys::argc() > 1 { sys::arg(1).unwrap_or(b"y") } else { b"y" };
    let mut line = [0u8; 64];
    let n = word.len().min(62);
    line[..n].copy_from_slice(&word[..n]);
    line[n] = b'\n';
    loop {
        let r = put(1, &line[..n + 1]);
        if r == sys::E_PIPE {
            return 0;
        }
        if r == sys::E_INTR {
            return 130;
        }
        if r < 0 {
            return 1;
        }
    }
}

fn spin() -> i32 {
    let _ = put(1, b"spin: computing (no syscalls) until stopped\n");
    let mut x: u64 = 1;
    loop {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        core::hint::black_box(x);
    }
}

fn sleep() -> i32 {
    let ms = sys::arg(1)
        .and_then(|a| {
            let mut v = 0u64;
            for &c in a {
                if !c.is_ascii_digit() {
                    return None;
                }
                v = v.saturating_mul(10).saturating_add((c - b'0') as u64);
            }
            Some(v)
        })
        .unwrap_or(1)
        .saturating_mul(1000);
    sys::sleep(ms);
    0
}

#[no_mangle]
pub extern "C" fn _start(_a0: usize, a1: usize) -> ! {
    sys::startup_init(a1);
    let name = sys::arg(0).unwrap_or(b"");
    // `argv[0]` may be a path: dispatch on its last component.
    let base = name.rsplit(|&b| b == b'/').next().unwrap_or(name);
    let code = match base {
        b"args" => args(),
        b"cat" => cat(),
        b"echo" => echo(),
        b"false" => 1,
        b"ls" => ls(),
        b"ps" => ps(),
        b"sleep" => sleep(),
        b"spin" => spin(),
        b"true" => 0,
        b"wc" => wc(),
        b"yes" => yes(),
        _ => {
            fail(b"toolbox", b"run as one of: args cat echo false ls ps sleep spin true wc yes");
            2
        }
    };
    sys::exit(code)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(70);
}

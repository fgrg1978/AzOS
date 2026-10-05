// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `POWER.ELF`: the user shell's power tool (RFC-0055 S5), the ring-3 form of
//! the recovery console's `pm suspend`, `reboot`, `shutdown` and `sched_hz`.
//!
//! Its topology row is the whole of its authority: `Cap<Power>` WRITE, found
//! with `SYS_CAP_LOOKUP` and presented to `SYS_POWER_TYPED` on every call. The
//! kernel checks it there, against the same authority table the recovery
//! console uses; this program decides nothing. Without the capability it still
//! asks, with handle 0, so the refusal is the kernel's and is recorded.
//!
//! Usage: `power suspend | reboot | shutdown | sched_hz [HZ]`. Exit 0 on
//! success, 1 when the kernel refused, 2 on a usage error.

#![no_std]
#![no_main]

use azos_libsys as sys;

fn put(fd: u64, b: &[u8]) {
    let mut done = 0usize;
    while done < b.len() {
        let r = sys::write(fd, &b[done..]);
        if r <= 0 {
            return;
        }
        done += r as usize;
    }
}

fn put_num(fd: u64, neg: bool, mut v: u64) {
    let mut d = [0u8; 21];
    let mut i = d.len();
    loop {
        i -= 1;
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    if neg {
        i -= 1;
        d[i] = b'-';
    }
    put(fd, &d[i..]);
}

fn parse(a: &[u8]) -> Option<u64> {
    if a.is_empty() || a.len() > 10 {
        return None;
    }
    let mut v = 0u64;
    for &b in a {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (b - b'0') as u64;
    }
    Some(v)
}

fn usage() -> i32 {
    put(2, b"usage: power suspend | reboot | shutdown | sched_hz [HZ]\n");
    2
}

/// Report a refusal or an error and return the exit code.
fn refused(what: &[u8], r: isize) -> i32 {
    put(2, b"power: ");
    put(2, what);
    put(2, b" refused: ");
    put_num(2, r < 0, r.unsigned_abs() as u64);
    put(2, b"\n");
    1
}

fn run() -> i32 {
    let op_name = sys::arg(1).unwrap_or(b"");
    let (op, arg) = match op_name {
        b"suspend" => (sys::power::POWER_OP_SUSPEND, 0),
        b"reboot" => (sys::power::POWER_OP_REBOOT, 0),
        b"shutdown" => (sys::power::POWER_OP_SHUTDOWN, 0),
        b"sched_hz" => match sys::arg(2) {
            None => (sys::power::POWER_OP_SCHED_HZ_GET, 0),
            Some(a) => match parse(a) {
                Some(hz) if (sys::power::POWER_SCHED_HZ_MIN..=sys::power::POWER_SCHED_HZ_MAX).contains(&hz) => (sys::power::POWER_OP_SCHED_HZ_SET, hz),
                _ => {
                    put(2, b"power: sched_hz takes 10..10000\n");
                    return 2;
                }
            },
        },
        _ => return usage(),
    };
    if sys::arg(3).is_some() || (op != sys::power::POWER_OP_SCHED_HZ_SET && sys::arg(2).is_some()) {
        return usage();
    }
    // Handle 0 when the row grants none: the kernel refuses and records it.
    let found = sys::cap_lookup(sys::CapKind::Power as u8, 0);
    let cap = if found >= 0 { found as u32 } else { 0 };
    let r = sys::power_typed(cap, op, arg);
    if r < 0 {
        return refused(op_name, r);
    }
    match op {
        sys::power::POWER_OP_SCHED_HZ_GET => {
            put(1, b"sched_hz ");
            put_num(1, false, r as u64);
            put(1, b"\n");
        }
        sys::power::POWER_OP_SCHED_HZ_SET => {
            put(1, b"sched_hz set ");
            put_num(1, false, arg);
            put(1, b"\n");
        }
        sys::power::POWER_OP_SUSPEND => put(1, b"power: resumed\n"),
        _ => {}
    }
    0
}

#[no_mangle]
pub extern "C" fn _start(_a0: usize, a1: usize) -> ! {
    sys::startup_init(a1);
    let code = run();
    sys::exit(code)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(70);
}

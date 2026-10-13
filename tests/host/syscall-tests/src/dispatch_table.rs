// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `syscall_table!` (crates/core/syscall/src/syscall_table.rs): the table it builds
//! answers exactly what the `match` of the same arms answered — first match
//! wins, or-patterns and ranges cover what they name, a `#[cfg]`'d-out arm is
//! absent, `_` fills the rest — and each handler receives every argument
//! under the name its arm spells.
//!
//! **Canaries.** In the macro, swap `$a0` and `$a1` in the handler's
//! parameters: `arguments_reach_the_names_the_arm_spells` is red. Bind
//! `$sepc` to `ctx.user_sp`: the same test is red. Drop `$(#[$attr])*` from
//! the arm: `the_table_answers_what_the_match_answered` is red (the cfg'd-out
//! arm claims 7).

use crate::syscall_table::{syscall_table, SysCtx, SyscallFn};

struct Regs {
    tag: u64,
}

#[derive(Default)]
struct Out {
    seen: Vec<(&'static str, u64)>,
}

const A: u64 = 3;
const B: u64 = 5;
const LO: u64 = 7;
const HI: u64 = 9;
const LEN: usize = 12;

fn tag(out: &mut Out, what: &'static str, v: u64) -> i64 {
    out.seen.push((what, v));
    v as i64
}

#[allow(unreachable_patterns)]
static TABLE: [SyscallFn<Regs, Out>; LEN] = syscall_table!(LEN, Regs, Out;
    |num, a0, a1, a2, a3, a4, a5, sepc, user_sp, regs, out| {
        A => tag(out, "a", 100 + a0),
        B | 6 => tag(out, "b", 200 + num),
        #[cfg(any())]
        LO => tag(out, "cfg'd out", 0),
        LO ..= HI => tag(out, "range", 300 + num),
        // Unreachable: `A` above wins, as it would in a `match`.
        A => tag(out, "shadowed", 0),
        10 => tag(out, "args", a0 + 10 * a1 + 100 * a2 + 1000 * a3 + 10_000 * a4 + 100_000 * a5),
        11 => tag(out, "ctx", num * 1_000_000 + sepc * 1000 + user_sp * 10 + regs.tag),
        _ => -1,
    });

fn call(n: u64, a: [u64; 6], sepc: u64, user_sp: u64, regs: &Regs, out: &mut Out) -> i64 {
    let mut ctx = SysCtx { sepc, user_sp, regs, out };
    TABLE[n as usize](n, a[0], a[1], a[2], a[3], a[4], a[5], &mut ctx)
}

#[test]
fn the_table_answers_what_the_match_answered() {
    let regs = Regs { tag: 0 };
    let expect: [(i64, Option<&str>); LEN] = [
        (-1, None), (-1, None), (-1, None),
        (101, Some("a")),
        (-1, None),
        (205, Some("b")), (206, Some("b")),
        (307, Some("range")), (308, Some("range")), (309, Some("range")),
        (1, Some("args")),
        (11_000_000, Some("ctx")),
    ];
    for n in 0..LEN as u64 {
        let mut out = Out::default();
        let got = call(n, [1, 0, 0, 0, 0, 0], 0, 0, &regs, &mut out);
        let (rc, what) = expect[n as usize];
        assert_eq!(got, rc, "number {n}");
        assert_eq!(out.seen.first().map(|s| s.0), what, "number {n} reached the wrong arm");
    }
}

#[test]
fn arguments_reach_the_names_the_arm_spells() {
    let regs = Regs { tag: 7 };
    let mut out = Out::default();
    assert_eq!(
        call(10, [1, 2, 3, 4, 5, 6], 0, 0, &regs, &mut out),
        654_321
    );
    assert_eq!(
        call(11, [0; 6], 5, 3, &regs, &mut out),
        11_005_037
    );
    assert_eq!(out.seen, vec![("args", 654_321), ("ctx", 11_005_037)], "`out` is the caller's");
}

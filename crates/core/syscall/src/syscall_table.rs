// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The syscall table: one handler per number, indexed, so every syscall costs
//! the same to reach (owner decision 2026-09-28, the `sys_call_table` shape).
//!
//! # Why not the `match`
//!
//! Dispatch used to be a `match num` of ~250 arms spread over 0..=610, in one
//! function. LLVM did lower it to a single bounded jump table (checked in the
//! riscv64 disassembly of 4992614), so the jump itself was already flat; what
//! was shared is everything after it. Every arm body was inlined into that one
//! function, with its register allocation, spills and block layout, so an
//! arm's cost depended on the whole function: wave 9 measured the notify calls
//! (592/593) 10 instructions dearer on aarch64 and 6 on riscv64, and
//! `ring-pingpong` 40 and 28, between two trees that differed by the 602 arm. Here
//! each arm is its own function behind one bounds check, one load and one
//! indirect call. Measured under `-icount` against 4992614 (aarch64/riscv64):
//! `syscall-floor` 212/318 unchanged, notify 495/647 -> 476/632,
//! `ring-pingpong` 3763/4618 -> 3681/4550, `ipc-roundtrip` 2198/2604 ->
//! 2190/2600.
//!
//! # Why a macro over the arms
//!
//! [`syscall_table!`] takes the arms of that `match` unchanged — `PATTERN =>
//! expression,`, `#[cfg]` included — and builds the table at compile time by
//! evaluating the same `match` once per number. So the table is, by
//! construction, what the `match` answered: the first arm that matches wins,
//! or-patterns and ranges mean what they meant, the `_` arm fills every number
//! nothing else claims, and the compiler still reports an unreachable arm.
//! Each arm becomes its own small `fn` whose body is the arm's expression, with
//! the old `match` locals (`num`, `a0`..`a5`, `sepc`, `user_sp`, `regs`,
//! `out`) bound under the names the caller spells. Moving the dispatch changed
//! no arm body.
//!
//! A handler takes `num, a0..a5` and a [`SysCtx`]: eight arguments, which the
//! Rust ABI passes in registers on riscv64 (`a0..a7`) and aarch64 (`x0..x7`),
//! in the order the dispatcher already holds them, so reaching a handler moves
//! no argument register. The values few arms read (`sepc`, `user_sp`, `regs`)
//! and the output registers travel in the context.
//!
//! Host-tested in `tests/host/syscall-tests/src/dispatch_table.rs`, which instantiates
//! the macro on arms of every shape.

/// What a handler receives besides `num` and `a0..a5`: the trapping PC and
/// user stack pointer and the saved user registers (read by fork only), and
/// the extra output registers (`SyscallOut` in the kernel).
pub struct SysCtx<'a, R, O> {
    pub sepc: u64,
    pub user_sp: u64,
    pub regs: &'a R,
    pub out: &'a mut O,
}

/// One entry of the table: `(num, a0, a1, a2, a3, a4, a5, ctx)`.
pub type SyscallFn<R, O> = fn(u64, u64, u64, u64, u64, u64, u64, &mut SysCtx<'_, R, O>) -> i64;

/// Build a `[SyscallFn<R, O>; LEN]` from `match` arms. See the module doc.
///
/// ```ignore
/// static TABLE: [SyscallFn<Regs, Out>; 16] = syscall_table!(16, Regs, Out;
///     |num, a0, a1, a2, a3, a4, a5, sepc, user_sp, regs, out| {
///         3 => f(a0),
///         4 | 5 => g(num, out),
///         _ => -1,
///     });
/// ```
///
/// Numbers `>= LEN` have no entry: the caller answers them itself.
macro_rules! syscall_table {
    (
        $len:expr, $regs_ty:ty, $out_ty:ty;
        |$num:ident, $a0:ident, $a1:ident, $a2:ident, $a3:ident, $a4:ident, $a5:ident,
         $sepc:ident, $user_sp:ident, $regs:ident, $out:ident| {
            $( $(#[$attr:meta])* $pat:pat => $body:expr, )*
        }
    ) => {{
        fn unset(
            _: u64, _: u64, _: u64, _: u64, _: u64, _: u64, _: u64,
            _: &mut $crate::syscall_table::SysCtx<'_, $regs_ty, $out_ty>,
        ) -> i64 {
            -1
        }
        let mut table: [$crate::syscall_table::SyscallFn<$regs_ty, $out_ty>; $len] = [unset; $len];
        let mut i = 0;
        while i < $len {
            table[i] = match i as u64 {
                $(
                    $(#[$attr])*
                    $pat => {
                        #[allow(unused_variables)]
                        fn arm(
                            $num: u64,
                            $a0: u64, $a1: u64, $a2: u64, $a3: u64, $a4: u64, $a5: u64,
                            ctx: &mut $crate::syscall_table::SysCtx<'_, $regs_ty, $out_ty>,
                        ) -> i64 {
                            let $sepc: u64 = ctx.sepc;
                            let $user_sp: u64 = ctx.user_sp;
                            let $regs: &$regs_ty = ctx.regs;
                            let $out: &mut $out_ty = &mut *ctx.out;
                            $body
                        }
                        arm
                    }
                )*
            };
            i += 1;
        }
        table
    }};
}
pub(crate) use syscall_table;

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The syscall flow, written once for every ISA.
//!
//! An ISA's entry asm saves the frame and calls a thin `extern "C"` wrapper
//! (`entry/<isa>/trap.rs`) that instantiates [`enter`] for its frame type; the
//! frame decode is the [`Frame`] impl next to it. In order:
//!
//! 1. interrupts on (owner decision O3.1: Linux model; the trap return masks
//!    them again before it touches `sepc` / `ELR` / `RCX`);
//! 2. the filter verdict: seccomp is the first thing every call meets, as it
//!    always was;
//! 3. **the prologue**: the entry tracepoint, the entry counted in the
//!    running Domain by the call's foundational case, and the Domain's pledge
//!    mask (`DOMAIN_PLEDGE`) asked whether it lets the call through;
//! 4. the call itself, unless the mask refused it (then the result is
//!    `-EACCES` and nothing ran): the two calls answered from the number alone
//!    (`getpid`, `yield`), the IPC fast path first when the entry is the lean
//!    one, else the dispatch; then the result, the exit tracepoint, the step
//!    over the trap instruction;
//! 5. at the return to user mode: an `exec`'s new frame, then signal and
//!    foreign-trap work.
//!
//! A Linux task's number is not in the native table, so its entry is counted in
//! the Domain's slot 0 (no case) and judged by the mask's bit 0. What a task may
//! call is two filters' to say: its `seccomp` filter's (per task, from its
//! image, native and Linux numbers alike), then its Domain's pledge (chosen by
//! the program, one way). `exit` and `thread_exit` are in every mask.

use azos_abi::error::Errno;
use azos_abi::invoke::pledge_bit;
use azos_abi::syscall_nr::syscall_case;

use super::frame::{EntryKind, Frame, SyscallServices};

/// The prologue of one syscall: its entry tracepoint, its entry counted by case
/// in the running Domain and judged by the Domain's pledge mask. The one place
/// the kernel counts an entry. `kind` is the filter's verdict: a Linux task's
/// number has no case. `false`: the mask refuses the call, which must not run.
#[inline(always)]
pub fn prologue<S: SyscallServices<F>, F: Frame>(frame: &F, num: u64, kind: EntryKind) -> bool {
    if S::trace_on() {
        S::trace_enter(num, frame.syscall_arg(0), frame.syscall_arg(1));
    }
    let linux = kind == EntryKind::Linux;
    S::domain_entry(num, if linux { 0 } else { syscall_case(num) }, pledge_bit(num, frame.syscall_arg(1), linux))
}

/// A syscall from user mode: everything between the trap and the return to
/// user mode. Returns the address-space word to install before the return, 0
/// to keep the one in force (an `exec` swaps it). `FAST`: the lean entry's IPC
/// branch, entered only for the two IPC fast calls (none of the register-only
/// calls can match): the fast path in this frame, and on a miss the ordinary
/// dispatch with the verdict already taken.
#[inline(always)]
pub fn enter<S: SyscallServices<F>, F: Frame, const FAST: bool>(frame: &mut F) -> u64 {
    let num = frame.syscall_number();
    if let Some(r) = S::probe(num) {
        return r;
    }
    S::interrupts_on();
    S::census_enter();
    let entry = S::verdict(num);
    let kind = S::kind(&entry);
    let result = if !prologue::<S, F>(frame, num, kind) {
        Errno::EACCES.to_syscall_ret()
    } else {
        match kind {
            _ if FAST => S::fast_or_dispatch(frame, num, entry),
            EntryKind::Native => match S::shortcut(num) {
                Some(r) => r,
                None => S::dispatch(frame, num, entry),
            },
            EntryKind::Linux => S::dispatch(frame, num, entry),
        }
    };
    frame.set_syscall_return(result);
    if S::trace_on() {
        S::trace_exit(num, result);
    }
    frame.skip_syscall();
    // The new image's frame, if this task ran `exec` inside this call.
    if let Some(ctx) = S::take_exec() {
        S::census_exit();
        return S::exec_enter(frame, ctx);
    }
    if S::return_work_pending() {
        S::return_work(frame);
    }
    S::census_exit();
    0
}

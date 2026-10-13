// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The registers a syscall hands back besides its result (`SyscallOut`). A
//! file of its own so the host suites that compile `invoke.rs` (whose replies
//! travel in it) need not compile the dispatcher; `dispatch` re-exports it.

/// Extra return registers a syscall arm may hand back to ring 3, on top of
/// the `i64` that lands in `a0`.
///
/// **WHY this exists (CARRIL 4).** `SYS_IPC_FAST_ACCEPT` has to give the
/// server a caller TID *and* four request words. One `i64` cannot carry
/// forty bytes, and fast IPC exists precisely so that ≤32 bytes travel in
/// registers without the kernel touching user memory — routing them through
/// a user pointer and `copy_to_user` would pay a per-page permission walk and
/// a copy on the one path this kernel optimises, forever, to avoid a one-time
/// six-line change in the trap handler.
///
/// The trap handler cannot simply be handed `&mut` to its register file: the
/// `reg_snapshot` it already passes as `regs` is a **copy** on its own stack
/// (it must be, because `frame.regs[10]` is overwritten with the return value
/// before a forked child ever reads it). So the out-registers travel back in
/// this struct and the handler copies them into the real `TrapFrame`.
///
/// **`written` is not decoration.** `a1`..`a5` are argument registers, and
/// every existing `libsys` wrapper passes its arguments as `in("a1")`,
/// `in("a2")`… — operands rustc is entitled to assume the `asm!` block leaves
/// untouched. Clobbering them on *every* syscall would be undefined behaviour
/// in ring 3 across the whole tree. Only an arm that explicitly opts in via
/// [`SyscallOut::set`] gets its registers copied back, and only wrappers
/// written for that arm may declare them `lateout`.
#[derive(Clone, Copy)]
pub struct SyscallOut {
    /// Values destined for `a1`..`a6`, in that order.
    pub regs: [u64; SYSCALL_OUT_REGS],
    /// True when an arm filled `regs` and the trap handler must copy them
    /// into the trap frame. False for every other syscall.
    pub written: bool,
}

/// What `a6` carries when no capability moved with the message.
///
/// Zero is not an accident of initialisation here: a capability handle is
/// generation-tagged and never zero, so ring 3 can read `a6 == 0` as "none"
/// without a separate flag.
pub const NO_CAP_MOVED: u64 = 0;

/// How many extra return registers [`SyscallOut`] carries: `a1`..`a6`.
///
/// **Was 5 until RFC-0040 gap 2 stage 4 (2026-09-20).** `SYS_IPC_FAST_ACCEPT`
/// already filled all five with `[caller_tid, w0, w1, w2, w3]` and returned the
/// exchange handle in `a0`, so a capability moved along with the message had
/// **nowhere to come back**. The sixth register is where the receiver learns
/// the handle the moved capability took in its own table; `0` means none rode.
///
/// `a7` (`regs[17]`) carries the syscall number and is never written back.
pub const SYSCALL_OUT_REGS: usize = 6;

impl SyscallOut {
    /// An empty set — nothing to copy back.
    pub const fn new() -> Self {
        Self { regs: [0; SYSCALL_OUT_REGS], written: false }
    }

    /// Opt this syscall into the copy-back and fill `a1`..`a6`.
    #[inline]
    pub fn set(&mut self, values: [u64; SYSCALL_OUT_REGS]) {
        self.regs = values;
        self.written = true;
    }

    /// [`set`](Self::set) for the arms that move no capability: fills `a1`..`a5`
    /// and puts [`NO_CAP_MOVED`] in `a6`.
    ///
    /// It exists so that adding the sixth register did not put a bare `0` at
    /// the end of three unrelated call sites, where it would read as a spare
    /// message word rather than as "no capability rode along". Every arm that
    /// does not transfer a capability must go through here, so the arms that
    /// DO are the only ones naming `a6` at all.
    #[inline]
    pub fn set_no_cap(&mut self, values: [u64; SYSCALL_OUT_REGS - 1]) {
        let mut regs = [NO_CAP_MOVED; SYSCALL_OUT_REGS];
        regs[..SYSCALL_OUT_REGS - 1].copy_from_slice(&values);
        self.regs = regs;
        self.written = true;
    }
}

impl Default for SyscallOut {
    fn default() -> Self { Self::new() }
}

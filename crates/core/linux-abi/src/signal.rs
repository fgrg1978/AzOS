// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Signal delivery's pure half (wave 13, RFC-0047 P3): what a Linux task's
//! signal frame looks like on each ISA, the default action of each signal,
//! the `sigaction` flags the personality honours, and the console's
//! canonical line discipline.
//!
//! Layouts are musl's (`arch/riscv64/bits/signal.h`,
//! `arch/aarch64/bits/signal.h`, `include/signal.h`), measured with the
//! toolchain BusyBox is built with: `ucontext_t` is 960 bytes on riscv64 and
//! 4560 on aarch64, `uc_sigmask` at 40 and `uc_mcontext` at 176 on both;
//! `siginfo_t` is 128 bytes. `tests/host/linux-abi-tests` pins them.
//!
//! The frame a handler is entered with is Linux's `rt_sigframe`: a
//! `siginfo_t`, then a `ucontext_t` (aarch64 adds a 16-byte frame record
//! after it). `sp` points at the `siginfo_t`; `a0`/`x0` is the signal,
//! `a1`/`x1` the `siginfo_t`, `a2`/`x2` the `ucontext_t`. The handler returns
//! to the restorer: on aarch64 the `sa_restorer` musl passes
//! (`SA_RESTORER`), on riscv64 (which has no `SA_RESTORER`) the kernel's
//! own sigreturn page. `rt_sigreturn` reads the `ucontext_t` back from the
//! same place.

use crate::Arch;

/// `sigaction` flags (`include/signal.h`; `SA_RESTORER` is aarch64's).
pub mod sa {
    pub const NOCLDSTOP: u64 = 1;
    pub const NOCLDWAIT: u64 = 2;
    pub const SIGINFO: u64 = 4;
    pub const RESTORER: u64 = 0x0400_0000;
    pub const ONSTACK: u64 = 0x0800_0000;
    pub const RESTART: u64 = 0x1000_0000;
    pub const NODEFER: u64 = 0x4000_0000;
    pub const RESETHAND: u64 = 0x8000_0000;
}

/// `si_code` values the kernel writes.
pub mod si {
    /// Sent by `kill`.
    pub const USER: i32 = 0;
    /// Raised by the kernel itself (console interrupt, broken pipe).
    pub const KERNEL: i32 = 0x80;
    /// Sent by `tkill`/`tgkill`.
    pub const TKILL: i32 = -6;
    /// `SIGCHLD`: the child exited.
    pub const CLD_EXITED: i32 = 1;
}

/// The signal mask bit of `sig` (1..=64), 0 for anything else.
pub const fn bit(sig: u64) -> u64 {
    if sig == 0 || sig > 64 { 0 } else { 1u64 << (sig - 1) }
}

/// The signals no mask blocks and no handler catches.
pub const UNBLOCKABLE: u64 = bit(crate::sig::SIGKILL) | bit(crate::sig::SIGSTOP);

/// What a signal does with no handler installed (`SIG_DFL`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultAction {
    /// End the task with exit code `128 + signo` (what `abitest` already
    /// proves for a native kill). Core-dumping signals end it the same way:
    /// no core is written.
    Terminate,
    /// Discarded.
    Ignore,
    /// Stop and continue: there is no job control here (no process groups
    /// in the POSIX subset), so these are discarded, and recorded as
    /// every delivery is.
    StopIgnored,
}

/// The default action of `sig` (Linux's table, stop signals discarded).
pub const fn default_action(sig: u64) -> DefaultAction {
    match sig {
        // SIGCHLD, SIGURG, SIGWINCH.
        17 | 23 | 28 => DefaultAction::Ignore,
        // SIGCONT, SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU.
        18..=22 => DefaultAction::StopIgnored,
        _ => DefaultAction::Terminate,
    }
}

/// Bytes of `siginfo_t`.
pub const SIGINFO_SIZE: usize = 128;
/// `ucontext_t.uc_sigmask` (both ISAs).
pub const UC_SIGMASK: usize = 40;
/// `ucontext_t.uc_stack.ss_flags`.
pub const UC_STACK_FLAGS: usize = 24;
/// `ucontext_t.uc_mcontext` (both ISAs: 16-byte aligned after a 128-byte
/// `sigset_t`).
pub const UC_MCONTEXT: usize = 176;
/// `SS_DISABLE`: no alternate stack.
pub const SS_DISABLE: u32 = 2;

/// riscv64: `sizeof(ucontext_t)`.
pub const RV_UC_SIZE: usize = 960;
/// riscv64: the FP state (`__riscv_mc_d_ext_state`) inside `mcontext_t`.
pub const RV_MC_FP: usize = 256;

/// aarch64: `sizeof(ucontext_t)`.
pub const A64_UC_SIZE: usize = 4560;
/// aarch64 `mcontext_t` offsets: `regs[31]`, `sp`, `pc`, `pstate`,
/// `__reserved` (where the `fpsimd_context` record goes).
pub const A64_MC_REGS: usize = 8;
pub const A64_MC_SP: usize = 256;
pub const A64_MC_PC: usize = 264;
pub const A64_MC_PSTATE: usize = 272;
pub const A64_MC_RESERVED: usize = 288;
/// `FPSIMD_MAGIC` and the record's size (head, fpsr, fpcr, 32 × 16 bytes).
pub const FPSIMD_MAGIC: u32 = 0x4650_8001;
pub const FPSIMD_SIZE: u32 = 528;
/// aarch64: the frame record `{fp, lr}` after the `ucontext_t`.
pub const A64_FRAME_RECORD: usize = 16;
/// aarch64 PSTATE bits a sigreturn may restore: N, Z, C, V. Everything else
/// is forced to EL0t with interrupts unmasked, whatever the frame says.
pub const A64_PSTATE_USER_MASK: u64 = 0xF000_0000;

/// Bytes of the whole frame on `arch`, before alignment.
pub const fn frame_size(arch: Arch) -> usize {
    match arch {
        Arch::Riscv64 => SIGINFO_SIZE + RV_UC_SIZE,
        Arch::Aarch64 => SIGINFO_SIZE + A64_UC_SIZE + A64_FRAME_RECORD,
    }
}

/// Where the frame goes below user stack pointer `sp`: 16-byte aligned, and
/// on riscv64 nothing more (no red zone on either ISA).
pub const fn frame_base(arch: Arch, sp: u64) -> u64 {
    sp.wrapping_sub(frame_size(arch) as u64) & !15
}

/// One interrupted user context's integer state, as the trap path holds it.
///
/// `gpr`: riscv64 `x0..x31` (`x2` is `sp`; `x0` is ignored), aarch64
/// `x0..x30` with `sp` in `gpr[31]`. `pstate` is aarch64's PSTATE (0 on
/// riscv64, where `sstatus` is never taken from a frame). The FP file and the
/// mask travel separately: the FP file straight between the registers and
/// the frame ([`fp_words`]), the mask through the scheduler's words.
#[derive(Clone, Copy)]
pub struct Context {
    pub gpr: [u64; 32],
    pub pc: u64,
    pub pstate: u64,
}

/// What `siginfo_t` says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Info {
    pub signo: u32,
    pub code: i32,
    /// The sender (`si_pid`), 0 for the kernel.
    pub pid: u32,
    /// `SIGCHLD`: the child's status (`si_status`).
    pub status: i32,
}

const W_UC: usize = SIGINFO_SIZE / 8;
const W_MC: usize = (SIGINFO_SIZE + UC_MCONTEXT) / 8;
/// aarch64: the `fpsimd_context` record's head word (or the null record
/// when the frame carries no FP file).
const W_A64_REC: usize = W_MC + A64_MC_RESERVED / 8;

/// riscv64 `uc_flags` bit: the frame carries the F/D file (the task had
/// used it). Without it the FP words are not written, and not read back.
pub const RV_UC_FP: u64 = 1;

/// Words from the frame base through the integer registers, the part every
/// frame writes and every `rt_sigreturn` reads: riscv64 through `__gregs`
/// (and `uc_flags`, whose bit [`RV_UC_FP`] says whether FP words follow),
/// aarch64 through the first record head (an `fpsimd_context` head or the
/// null record).
pub const fn head_words(arch: Arch) -> usize {
    match arch {
        Arch::Riscv64 => W_MC + 32,
        Arch::Aarch64 => W_A64_REC + 1,
    }
}

/// The words of the frame that hold the FP file: riscv64 `f0..f31` then a
/// word whose low half is `fcsr` (the kernel's save-area layout exactly);
/// aarch64 one word `fpsr | fpcr << 32` then `v0..v31` (two words each),
/// inside the `fpsimd_context` record.
pub const fn fp_words(arch: Arch) -> core::ops::Range<usize> {
    match arch {
        Arch::Riscv64 => W_MC + RV_MC_FP / 8..W_MC + RV_MC_FP / 8 + 33,
        Arch::Aarch64 => W_A64_REC + 1..W_A64_REC + 66,
    }
}

/// Words a frame with an FP file spans from its base (aarch64: through the
/// null record after `fpsimd_context`). The rest of aarch64's `__reserved`
/// (room for records this kernel never writes) is left as the user's own
/// stack had it, as Linux leaves it; the frame record after the
/// `ucontext_t` is two words of its own ([`a64_frame_record_word`]).
pub const fn frame_words(arch: Arch) -> usize {
    match arch {
        Arch::Riscv64 => fp_words(arch).end,
        Arch::Aarch64 => fp_words(arch).end + 1,
    }
}

/// The most words [`frame_words`] is on any ISA.
pub const FRAME_WORDS_MAX: usize = W_A64_REC + 67;

/// aarch64: the word index (from the frame base) of the frame record
/// `{fp, lr}` after the `ucontext_t`.
pub const fn a64_frame_record_word() -> usize {
    (SIGINFO_SIZE + A64_UC_SIZE) / 8
}

/// Write the frame for `ctx`, mask `mask` and `info` into `w`. Every word
/// the kernel copies out is written here (no kernel word reaches the user
/// stack), except the FP words when `fp` says the caller fills them
/// ([`fp_words`]). Returns how many words to copy from the base:
/// [`head_words`] without FP (aarch64: plus nothing, the head word is then
/// the null record), [`frame_words`] with it. `None` if `w` is short.
pub fn write_frame(arch: Arch, w: &mut [u64], ctx: &Context, mask: u64, info: &Info, fp: bool) -> Option<usize> {
    if w.len() < frame_words(arch) {
        return None;
    }
    // siginfo_t: si_signo, si_errno | si_code, then si_pid | si_uid,
    // si_status; the rest zero.
    w[0] = info.signo as u64;
    w[1] = info.code as u32 as u64;
    w[2] = info.pid as u64;
    w[3] = info.status as u32 as u64;
    w[4..W_UC].fill(0);
    // ucontext_t: uc_flags, uc_link, uc_stack {sp, flags, size}, uc_sigmask
    // (8 bytes of mask in a 128-byte set), padding to uc_mcontext.
    w[W_UC] = if arch == Arch::Riscv64 && fp { RV_UC_FP } else { 0 };
    w[W_UC + 1] = 0;
    w[W_UC + 2] = 0;
    w[W_UC + UC_STACK_FLAGS / 8] = SS_DISABLE as u64;
    w[W_UC + 4] = 0;
    w[W_UC + UC_SIGMASK / 8] = mask;
    w[W_UC + UC_SIGMASK / 8 + 1..W_MC].fill(0);
    Some(match arch {
        Arch::Riscv64 => {
            // __gregs[0] is the pc; [1..32] are x1..x31.
            w[W_MC] = ctx.pc;
            w[W_MC + 1..W_MC + 32].copy_from_slice(&ctx.gpr[1..32]);
            if fp { frame_words(arch) } else { head_words(arch) }
        }
        Arch::Aarch64 => {
            w[W_MC] = 0; // fault_address
            let r = W_MC + A64_MC_REGS / 8;
            w[r..r + 31].copy_from_slice(&ctx.gpr[..31]);
            w[W_MC + A64_MC_SP / 8] = ctx.gpr[31];
            w[W_MC + A64_MC_PC / 8] = ctx.pc;
            w[W_MC + A64_MC_PSTATE / 8] = ctx.pstate;
            w[W_MC + A64_MC_PSTATE / 8 + 1] = 0;
            if fp {
                w[W_A64_REC] = FPSIMD_MAGIC as u64 | (FPSIMD_SIZE as u64) << 32;
                w[fp_words(arch).end] = 0;
                frame_words(arch)
            } else {
                w[W_A64_REC] = 0;
                head_words(arch)
            }
        }
    })
}

/// Read the integer context and the mask back from `w` (the frame's first
/// [`head_words`] words), as `rt_sigreturn` does. Every value is the user's
/// own: the mask never blocks `SIGKILL`/`SIGSTOP`, and aarch64's PSTATE
/// comes back as N, Z, C, V only. The `bool` says whether FP words follow
/// (to be read from [`fp_words`]). `None` if `w` is short.
pub fn read_frame(arch: Arch, w: &[u64]) -> Option<(Context, u64, bool)> {
    if w.len() < head_words(arch) {
        return None;
    }
    let mask = w[W_UC + UC_SIGMASK / 8] & !UNBLOCKABLE;
    let mut gpr = [0u64; 32];
    Some(match arch {
        Arch::Riscv64 => {
            gpr[1..32].copy_from_slice(&w[W_MC + 1..W_MC + 32]);
            (Context { gpr, pc: w[W_MC], pstate: 0 }, mask, w[W_UC] & RV_UC_FP != 0)
        }
        Arch::Aarch64 => {
            let r = W_MC + A64_MC_REGS / 8;
            gpr[..31].copy_from_slice(&w[r..r + 31]);
            gpr[31] = w[W_MC + A64_MC_SP / 8];
            let pstate = w[W_MC + A64_MC_PSTATE / 8] & A64_PSTATE_USER_MASK;
            let fp = w[W_A64_REC] == FPSIMD_MAGIC as u64 | (FPSIMD_SIZE as u64) << 32;
            (Context { gpr, pc: w[W_MC + A64_MC_PC / 8], pstate }, mask, fp)
        }
    })
}

/// The riscv64 sigreturn trampoline: `li a7, 139; ecall`. The kernel maps it
/// read-execute into every user address space (riscv64 musl has no
/// `SA_RESTORER`; Linux's own riscv64 kernel returns through its vDSO the
/// same way).
pub const RV_SIGRETURN_CODE: [u32; 2] = [
    0x08b0_0893, // addi a7, zero, 139
    0x0000_0073, // ecall
];

// ── The console's line discipline ───────────────────────────────────────────

/// Bytes of one input line the console keeps.
pub const LINE_MAX: usize = 256;

/// What a byte fed to [`LineDisc`] asks of the kernel beyond echo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feed {
    /// Nothing more.
    None,
    /// The interrupt or quit character: raise this signal (the line so far
    /// is dropped, as `ISIG` without `NOFLSH` does).
    Signal(u64),
}

/// The canonical line discipline the console reports in its termios
/// (`ICANON | ECHO | ISIG`, `ICRNL`, `ONLCR`), for a Linux task reading
/// the console: a line is handed out only once it is complete (newline or
/// `VEOF`), typed bytes are echoed, `VERASE` (DEL or backspace) and `VKILL`
/// (`^U`) edit the line, `VEOF` (`^D`) on an empty line is end of file, and
/// `VINTR`/`VQUIT` (`^C`/`^\`) become signals.
pub struct LineDisc {
    buf: [u8; LINE_MAX],
    /// Bytes in `buf`.
    len: usize,
    /// Bytes at the front of `buf` that make complete lines.
    ready: usize,
    /// A `VEOF` on an empty line is waiting to be read as end of file.
    eof: bool,
}

impl Default for LineDisc {
    fn default() -> Self {
        Self::new()
    }
}

impl LineDisc {
    pub const fn new() -> Self {
        Self { buf: [0; LINE_MAX], len: 0, ready: 0, eof: false }
    }

    /// Feed one input byte; `echo` receives what the terminal shows.
    pub fn feed(&mut self, c: u8, echo: &mut dyn FnMut(&[u8])) -> Feed {
        match c {
            0x03 | 0x1c => {
                self.flush_partial();
                echo(if c == 0x03 { b"^C\n" } else { b"^\\\n" });
                return Feed::Signal(if c == 0x03 { crate::sig::SIGINT } else { SIGQUIT });
            }
            // VERASE: DEL or backspace.
            0x7f | 0x08 => {
                if self.len > self.ready {
                    self.len -= 1;
                    echo(b"\x08 \x08");
                }
            }
            // VKILL.
            0x15 => {
                while self.len > self.ready {
                    self.len -= 1;
                    echo(b"\x08 \x08");
                }
            }
            // VEOF: ends the line without a byte; on an empty line, EOF.
            0x04 => {
                if self.len == self.ready {
                    self.eof = true;
                } else {
                    self.ready = self.len;
                }
            }
            // ICRNL, then NL ends the line.
            b'\r' | b'\n' => {
                if self.len < LINE_MAX {
                    self.buf[self.len] = b'\n';
                    self.len += 1;
                } else {
                    // A full line still ends: its last byte becomes the
                    // newline, so a reader is never stuck behind it.
                    self.buf[LINE_MAX - 1] = b'\n';
                }
                self.ready = self.len;
                echo(b"\n");
            }
            _ => {
                // A full line keeps one byte for its newline.
                if self.len < LINE_MAX - 1 {
                    self.buf[self.len] = c;
                    self.len += 1;
                    echo(&[c]);
                }
            }
        }
        Feed::None
    }

    /// Hand out up to `out.len()` bytes of complete lines: `Some(n)` (`0` is
    /// end of file), `None` when no complete line is waiting.
    pub fn take(&mut self, out: &mut [u8]) -> Option<usize> {
        if self.ready > 0 {
            let n = self.ready.min(out.len());
            out[..n].copy_from_slice(&self.buf[..n]);
            self.buf.copy_within(n..self.len, 0);
            self.len -= n;
            self.ready -= n;
            return Some(n);
        }
        if self.eof {
            self.eof = false;
            return Some(0);
        }
        None
    }

    /// Drop the line being typed (complete lines stay).
    pub fn flush_partial(&mut self) {
        self.len = self.ready;
    }

    /// Drop everything, complete lines included (`^C` from the interrupt).
    pub fn flush_all(&mut self) {
        self.len = 0;
        self.ready = 0;
        self.eof = false;
    }
}

/// `SIGQUIT`.
pub const SIGQUIT: u64 = 3;

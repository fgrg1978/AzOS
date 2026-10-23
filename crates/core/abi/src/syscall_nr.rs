// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The native syscall table.
//!
//! These are the **canonical** definitions. `crates/core/syscall`
//! (`crates/core/syscall/src/numbers.rs`) re-exports this module verbatim rather
//! than restating it, and `crates/core/libsys` imports the names it needs from
//! here directly — neither crate keeps an independent copy of a number.
//!
//! ## The table
//!
//! Thirty-three calls, dense from 1, in families. Nothing else is a syscall:
//! every operation on an object the caller holds a handle to — the files,
//! sockets it opened, its own domain, the console, a port, a memory
//! object — is an *op* of [`SYS_INVOKE`] (`crate::invoke`), selected by the
//! handle's type and an op word, and gated by the image's profile at the grain
//! of an op *class* (`azos_sched::seccomp`).
//!
//! | Family      | Calls |
//! |-------------|-------|
//! | handles     | [`SYS_CAP_INFO`], [`SYS_CAP_CLOSE`], [`SYS_CAP_DERIVE`], [`SYS_CAP_REVOKE`] |
//! | domain      | [`SYS_SPAWN_EX`], [`SYS_THREAD_CREATE`], [`SYS_THREAD_EXIT`], [`SYS_EXIT`], [`SYS_ALERT`], [`SYS_GETPID`] |
//! | time, sched | [`SYS_YIELD`], [`SYS_SLEEP_UNTIL`], [`SYS_SCHEDCTL`] |
//! | memory      | [`SYS_MO_CREATE`], [`SYS_MO_MAP`], [`SYS_MO_UNMAP`] |
//! | IPC         | [`SYS_IPC_FAST_CALL_EP`], [`SYS_IPC_FAST_REPLY`], [`SYS_IPC_FAST_ACCEPT`], [`SYS_IPC_FAST_REPLY_ACCEPT`], [`SYS_IPC_CALL_V2`], [`SYS_IPC_ACCEPT_V2`], [`SYS_IPC_REPLY_V2`], [`SYS_IPC_REPLY_DELEGATE`], [`SYS_RING_SETUP`], [`SYS_RING_ENTER`], [`SYS_PORT_WAIT`] |
//! | futex       | [`SYS_FUTEX_WAIT`], [`SYS_FUTEX_WAKE`] |
//! | foreign ABI | [`SYS_FOREIGN_ENTRY`], [`SYS_FOREIGN_RESUME`], [`SYS_FOREIGN_FORK`] |
//! | generic     | [`SYS_INVOKE`] |
//!
//! There is no compatibility promise inside a pre-release series: a number is
//! renumbered in place when the table changes, and [`crate::ABI_VERSION`]
//! (carried in every `libsys` image as an ELF note, published by the kernel in
//! the vDSO) is what a program and a kernel compare. Linux programs use the
//! Linux numbers, which the in-kernel personality or the ring-3 runtime
//! translates; they are not in this table.
//!

//! ## Register convention (per ISA)
//!
//! The numbers are ISA-independent — `SYS_GETPID` is `10` on every
//! target this ABI reaches. Which *registers* carry the number, the
//! arguments and the result is a per-ISA convention, established here so the
//! kernel side (`kernel/**`, `crates/core/arch-*/**`) implements exactly this
//! rather than inventing its own mapping.
//!
//! ### RISC-V64 (established, `crates/core/libsys`)
//!
//! | Role                                   | Register(s)   |
//! |-----------------------------------------|---------------|
//! | Syscall number                           | `a7`          |
//! | Arguments (up to 6)                      | `a0..=a5`     |
//! | Primary result (`isize`, negative=error) | `a0`          |
//! | Fast-IPC extra outputs (up to 6)         | `a1..=a6`     |
//!
//! Trap instruction: `ecall`. The fast-IPC family (`SYS_IPC_FAST_CALL_EP` and
//! kin, and `SYS_INVOKE`'s register-form replies) is the only one that uses `a6` — every other syscall's kernel-written
//! output is `a0` alone, and a wrapper that does not declare every register
//! the kernel writes as `lateout`/`inlateout` invites the exact class of bug
//! `crates/core/libsys/src/lib.rs` documents on `trace_dump` and the fast-IPC
//! functions: an `asm!` that leaves a result register `in`-only lets rustc
//! assume it survives the trap, and the kernel overwriting it is then
//! undefined behaviour, not a wrong answer.
//!
//! ### AArch64 (`aarch64-unknown-none`, hard-float,
//! ARMv8.5 baseline, owner decision 97)
//!
//! | Role                                   | Register(s)   |
//! |-----------------------------------------|---------------|
//! | Syscall number                           | `x8`          |
//! | Arguments (up to 6)                      | `x0..=x5`     |
//! | Primary result (`isize`, negative=error) | `x0`          |
//! | Fast-IPC extra outputs (up to 6)         | `x1..=x6`     |
//!
//! Trap instruction: `svc #0`. The immediate operand is not read by this
//! convention (`ESR_EL1.EC == 0x15`, `ISS` ignored) — the number travels in
//! `x8` exactly as on RISC-V it travels in `a7`, which is also the register
//! Linux's own aarch64 `svc` ABI reserves for the same purpose. This is a
//! direct, register-for-register analogue of the RISC-V convention:
//! `x0..=x5` mirrors `a0..=a5`, `x0` mirrors `a0`, and the fast-IPC family's
//! extra outputs `x1..=x6` mirror `a1..=a6`. Choosing anything else — e.g.
//! reusing `x8` for a return value, or spreading arguments across `x0..=x7`
//! — would make the two ISAs' wrapper code diverge for no reason the ABI
//! needs; `crates/core/libsys` relies on this symmetry to keep one function body
//! per syscall, `#[cfg(target_arch = ..)]`-selecting only the `asm!` block
//! inside it.
//!
//! `x6` and `x7` are otherwise unused by this convention (no syscall takes
//! more than 6 arguments, matching RISC-V's `a0..=a5`), so `x7` carries
//! nothing in either direction.
//!
//! ### x86_64
//!
//! | Role                                   | Register(s)                         |
//! |-----------------------------------------|-------------------------------------|
//! | Syscall number                           | `rax`                               |
//! | Arguments (up to 6)                      | `rdi, rsi, rdx, r10, r8, r9`        |
//! | Primary result (`isize`, negative=error) | `rax`                               |
//! | Fast-IPC extra outputs (up to 6)         | `rdx, rsi, rdi, r8, r9, r10`        |
//!
//! Trap instruction: `syscall`, which itself loads `rcx` with the return
//! RIP and `r11` with RFLAGS.
//!
//! ## Register contract (Chain E commit 8, owner decision 2026-10-12)
//!
//! **Every native syscall**, not only IPC: on return, ring 3 may rely on
//! exactly these holding what it left in them:
//!
//!   * the callee-saved registers of the platform calling convention:
//!     riscv64 `s0..=s11`; aarch64 `x19..=x29` (and the low halves of
//!     `v8..=v15`) and `x18`, the platform register rustc reserves on this
//!     target (no `asm!` can declare it clobbered); x86_64 `rbx, rbp,
//!     r12..=r15`;
//!   * the stack and thread pointers: riscv64 `sp, gp, tp`; aarch64 `sp`
//!     (`SP_EL0`) and `TPIDR_EL0`; x86_64 `rsp` and the FS/GS bases;
//!   * the link register: riscv64 `ra`, aarch64 `x30`. Caller-saved in the
//!     calling convention, but kept: declared clobbered, it made every leaf
//!     around a syscall save and restore it (vsbench riscv64, fork+exit
//!     +3.3%, clock `vdso` +8%), and the kernel keeps it for one store;
//!   * the syscall's documented outputs: the result register, and the
//!     extra outputs (`a1..=a6` / `x1..=x6` / `rdx, rsi, rdi, r8..=r10`)
//!     where the call writes them; an extra output the call does not write
//!     comes back as the caller passed it.
//!
//! Everything else is **clobbered**: riscv64 `t0..=t6, a7`; aarch64
//! `x7..=x17` (`x8`, the number, included); x86_64 `rcx, r11`. Every
//! ring-3 stub declares them (`lateout(..) _`, see `crates/core/libsys`'s
//! `syscall0..=syscall6`), and an `asm!` that issues the trap with values
//! of its own live across it keeps them in callee-saved registers.
//!
//! What the kernel does with that freedom (Kconfig `SYSCALL_LEAN_ENTRY`,
//! default y): a native task's syscall takes a trap-entry path that does
//! not store the clobbered registers, and returns them **zeroed**, never a
//! kernel value. aarch64 keeps `x7..=x9` (each pairs with a register it
//! stores anyway), x86_64 returns `rcx`/`r11` as `sysret`
//! defines them (the return RIP and RFLAGS). A trap that is not a syscall
//! saves and restores everything; a forked child starts with the clobbered
//! registers zero.
//!
//! **A successful exec does not return**, so none of the above applies to
//! it: the new image starts with every general-purpose register zero but
//! its stack pointer (x86_64: `rcx`/`r11` as `sysret` defines them), both
//! personalities, and a Linux image also without a thread pointer
//! (`TPIDR_EL0` / FS base zero; riscv64's `tp` is a register of the file).
//! Nothing of the old image's file reaches the new one, which may hold
//! another authority (its own filter and row).
//!
//! **A Linux-personality task keeps the Linux ABI**: every
//! register but the documented results is preserved, through the full save
//! (riscv64 and aarch64 tag a task's trap frame at its first entry to user
//! mode; the x86_64 Linux ABI clobbers `rcx`/`r11` as well).
//!
//! ### What the kernel must preserve
//!
//! Same rule stated for the register set that applies to it:
//!
//!   * The register contract above. `SyscallOut`-style arms (the
//!     fast-IPC family) may additionally write `x1..=x6`, and MUST write
//!     every one of them on every path — success and failure alike —
//!     because a caller that declares them `lateout` (not `inlateout`) is
//!     entitled to assume the trap clobbers them regardless of outcome; an
//!     arm that writes them only on success reproduces the `trace_dump` bug
//!     `crates/core/libsys` already found and fixed on the RISC-V side.
//!   * `SP_EL0` must be 16-byte aligned at every `_start` entry. Unlike
//!     RISC-V (no stack-alignment trap), `SCTLR_EL1.SA0` — if the kernel
//!     enables it — faults a misaligned `sp` on the very first stack access
//!     in EL0, before any user code runs. The linker starts every segment
//!     of a native image on a page of its own already (W^X); stack
//!     alignment is the loader's job (where it sets the initial `sp`), not
//!     the linker's.
//!   * This target is hard-float (owner decision 97: ARMv8.5 baseline,
//!     NEON mandatory) — unlike RISC-V's `imac` baseline, which has no
//!     vector state to save. If any ring-3 program uses NEON, the trap
//!     entry/exit must save/restore `v0..=v31`, `fpsr` and `fpcr` around the
//!     syscall, or a user task's vector registers are silently clobbered by
//!     whatever the kernel's own trap path touches. `crates/core/libsys`'s
//!     wrappers do not use NEON themselves and declare no vector-register
//!     clobbers; that is a statement about `libsys`, not permission for the
//!     kernel to skip saving them for callers that do use NEON elsewhere in
//!     the same task.
//!   * The AArch64 analogue of `crates/core/libsys`'s `rdtime` (the RISC-V `time`
//!     CSR read from ring 3, `scounteren.TM`) is `mrs {}, cntvct_el0`, and it
//!     needs `CNTKCTL_EL1.EL0VCTEN` set for EL0 to read it without trapping.
//!     The kernel sets it at boot, and installs the same vDSO page as on the
//!     other ISAs, so `crates/core/libsys`'s aarch64 `read_time_csr` twin reads
//!     the counter unconditionally: the `VDSO_FLAG_RDTIME_NATIVE` flag
//!     (`vdso_rdtime_native`) is the "native vs. must-trap" distinction of
//!     RISC-V's `time` CSR alone.

#![allow(missing_docs)]

// ── Register convention constants (documentation aid, not wire format) ──
//
// Plain string/array constants so a scanner or a future doc can name "the
// syscall-number register for ISA X" without restating the literal — see
// the module doc's "Register convention" section above for what each one
// means and why. Not part of any wire format: nothing serializes these:
// they name assembly registers, not bytes that cross the user/kernel
// boundary.

/// RISC-V64: the syscall-number register (`a7`).
pub const REG_NR_RISCV64: &str = "a7";
/// RISC-V64: the up-to-6 argument registers, in order (`a0..=a5`).
pub const REG_ARGS_RISCV64: [&str; 6] = ["a0", "a1", "a2", "a3", "a4", "a5"];
/// RISC-V64: the primary result register (`a0`).
pub const REG_RESULT_RISCV64: &str = "a0";
/// RISC-V64: the fast-IPC family's extra output registers beyond the
/// primary result (`a1..=a6`).
pub const REG_FAST_IPC_OUT_RISCV64: [&str; 6] = ["a1", "a2", "a3", "a4", "a5", "a6"];
/// AArch64: the syscall-number register (`x8`).
pub const REG_NR_AARCH64: &str = "x8";
/// AArch64: the up-to-6 argument registers, in order (`x0..=x5`).
pub const REG_ARGS_AARCH64: [&str; 6] = ["x0", "x1", "x2", "x3", "x4", "x5"];
/// AArch64: the primary result register (`x0`).
pub const REG_RESULT_AARCH64: &str = "x0";
/// AArch64: the fast-IPC family's extra output registers beyond the
/// primary result (`x1..=x6`).
pub const REG_FAST_IPC_OUT_AARCH64: [&str; 6] = ["x1", "x2", "x3", "x4", "x5", "x6"];
/// The value of the second argument register (riscv64 `a1`, aarch64 `x1`,
/// x86_64 `rsi`) on which a kernel built with the canary feature
/// `syscall-abi-canary` flips bit 0 of one callee-saved register (s3, x20,
/// rbx) on the native syscall exit. abitest's callee-saved check passes it,
/// so that check, and only that check, goes red under the canary. Not wire
/// format: no kernel without the feature looks at it.
pub const SYSCALL_ABI_CANARY_A1: u64 = 0x0CA1_1EE5;

// ── Handles ───────────────────────────────────────────────────────────

/// `SYS_CAP_INFO` — what the caller holds, without using it: `a0` a handle (the
/// query that takes none ignores it), `a1` the query, `a2` and `a3` its
/// arguments. Naming a capability is not using one: no right is needed and
/// containment does not apply.
///
///   * [`CAP_INFO_LOOKUP`]: the caller's handle for the capability of type
///     `a2` (a `CapType` raw value) that names resource `a3` (for a kernel-hosted
///     `Endpoint`: `host_key << 32 | badge`); `-ENOENT` if it holds none,
///     `-EINVAL` for a type that does not exist.
///   * [`CAP_INFO_TREE`]: the caller's handle for the directory tree
///     (`ty::FILE`, a tree resource) that covers the NUL-terminated absolute
///     path at `a2`; `-ENOENT` if it holds none.
///   * [`CAP_INFO_QUERY`]: of the handle `a0`: the type raw value in bits 0..8 and
///     the rights (`CapPerms`, six bits) in bits 8..14 of the result; the badge in `a1` and the
///     expiry (absolute ns on the MONO clock, 0 none) in `a2` of the reply.
///     `-ECAPSTALE` for a handle the caller does not hold.
///
/// Foundational case 1 (authority: the handle table is kernel state).
pub const SYS_CAP_INFO: u64 = 1;

/// `SYS_CAP_CLOSE` — `a0` a handle: delete the capability and release what it
/// names, chosen by its type (a file, a socket, an io_ring, a
/// port, a memory object). Only the caller's own slot goes: a copy made from
/// the handle (a DUP over IPC, a spawn's share) stays alive in its holder's
/// table and keeps its mappings; [`SYS_CAP_REVOKE`] is what takes copies back.
/// A handle of a type with nothing to release is just deleted. A second close
/// of one handle is `-ECAPSTALE`. The one call that ends a handle's life.
///
/// Foundational case 1 (authority: a handle's life ends only by its holder).
pub const SYS_CAP_CLOSE: u64 = 2;

/// `SYS_CAP_DERIVE` — `a0` a held endpoint capability with `DUP`, `a1` the
/// rights of the copy (a subset of the source's), `a2` its badge (non-zero,
/// the source unbadged), `a3` an expiry (absolute ns on the MONO clock; 0 none;
/// the earlier of it and the source's is kept). Mints the copy into the
/// caller's table as a child of the source in the warrant tree, so revoking
/// the source ([`SYS_CAP_REVOKE`]) revokes it. Returns the new handle. A
/// kernel-hosted endpoint refuses: its badge is the resource, and only the
/// kernel stamps it.
///
/// Foundational case 1 (authority: a child capability enters the warrant tree).
pub const SYS_CAP_DERIVE: u64 = 3;

/// `SYS_CAP_REVOKE` — `a0` a held handle: revoke every capability derived from
/// it (here and in any task they were lent or moved to) and keep it. The
/// handle changes: the call returns the replacement, and the old value is
/// stale. A server uses it to withdraw what it lent.
///
/// Foundational case 1 (authority: withdraws what was lent).
pub const SYS_CAP_REVOKE: u64 = 4;

/// [`SYS_CAP_INFO`] query: find a held capability by type and resource.
pub const CAP_INFO_LOOKUP: u64 = 0;

/// [`SYS_CAP_INFO`] query: find the held directory tree covering a path.
pub const CAP_INFO_TREE: u64 = 1;

/// [`SYS_CAP_INFO`] query: read a held capability's type, rights, badge and
/// expiry.
pub const CAP_INFO_QUERY: u64 = 2;


// ── Domain and threads ────────────────────────────────────────────────

/// `SYS_SPAWN_EX` — `a0 = path`, `a1 = *const SpawnReq` (0: no request). The
/// native process creation call: it starts the image at the path under the
/// seccomp profile bound to the image's SHA-256, with the capabilities of the
/// topology row named after it (digest-bound profile, row, class, budget),
/// and the caller must hold a `Cap<Launch>` with `EXEC` for the image the
/// digest resolves to. A request block adds: argv, environment and a working
/// directory written into the child as a `StartupBlock` whose address the
/// child receives in `a1` (`x1`) — not `a0`, which the spawn hand-off zeroes
/// as fork's does; a move list (at most 8) that MOVES the caller's
/// `Cap<File>` descriptors into the child as its fds 0..7 (a
/// `Cap<Shm>`, a POSIX pipe's region, is shared instead: the caller keeps its
/// own), rights kept or lowered, never raised; `SPAWN_F_DIE_WITH_PARENT`. Returns the
/// child's TID, or `-EACCES` (no profile, no row, no launch grant),
/// `-ECAPKIND`, `-ECAPPERMS`, `-ECAPSTALE`, `-EMFILE`, `-EINVAL` (version,
/// limits, unknown flag), `-EFAULT`, `-1` for an unreadable path. Nothing moves
/// unless the child is released.
///
/// Foundational case 1 (authority: creates a protection domain).
pub const SYS_SPAWN_EX: u64 = 5;

/// `SYS_THREAD_CREATE` — wave 13 (THREADS): a new thread of the calling
/// task's process. `a0` = user entry PC, `a1` = its stack pointer (16-byte
/// aligned top), `a2` = an argument, `a3` = the address of a 32-bit word its
/// exit clears and futex-wakes (0: none; what a join waits on), `a4` = its
/// thread pointer (`tp` / `TPIDR_EL0`; 0: the creator's).
///
/// The thread shares the caller's address space, capability table and
/// descriptor table; it is created in the caller's class at its base
/// priority under its seccomp filter. It starts at `a0` with the caller's
/// registers at the call except the stack pointer, the thread pointer and
/// the first argument register, which is 0: the entry sees `(0, stack, arg,
/// ctid, tls)` in its first five argument registers. Returns the new TID,
/// `-EAGAIN` (a group already has `GROUP_THREADS_MAX` = 16 live threads,
/// [`GROUPS_MAX`] = 8 multi-thread processes exist, the task pool is full,
/// or the process is ending), `-1` for a caller with no user address space
/// or a zero stack.
///
/// Foundational case 1 (authority: a new schedulable context in the caller's domain).
pub const SYS_THREAD_CREATE: u64 = 6;

/// `SYS_THREAD_EXIT` — wave 13: end only the calling thread, with `a0` as
/// its code (a thread's code is reported to nobody). Its clear-tid word is
/// cleared and woken. The process's last thread ending ends the process; a
/// process's first thread (its leader) that ends while others run waits in
/// the kernel for them and then reports. `SYS_EXIT` from any thread ends the
/// whole process (every other thread is stopped). Does not return.
///
/// Foundational case 1 (protection: only the kernel can retire a context and its stack).
pub const SYS_THREAD_EXIT: u64 = 7;

/// `SYS_EXIT` — `a0` = the exit code. Ends the whole process (every thread of
/// it); the parent learns the code from the wait op of its domain. Does not
/// return.
///
/// Foundational case 1 (protection: only the kernel can tear a domain down).
pub const SYS_EXIT: u64 = 8;

/// `SYS_ALERT` — `a0 = tid`, `a1 = how` (`KILL_REQUEST` | `KILL_FORCE`),
/// `a2 = signo` (1..=31), `a3 = flags` (`KILL_SUBTREE`). Tell a task of the
/// caller's own descendants to stop. The caller must be an ANCESTOR of `tid`
/// (parent chain, at most 8 steps); anything else, absent included, is
/// `-ESRCH`; self is `-EINVAL`. A request wakes the target's interruptible
/// waits with `-EINTR`; force also ends it at its next return to user mode (or
/// at that wake) with exit code `128 + signo`, by the path a user-mode fault
/// takes, never inside a syscall. Returns how many tasks were signalled (at
/// least 1).
///
/// Foundational case 1 (authority: a forced kill of another task).
pub const SYS_ALERT: u64 = 9;

/// `SYS_GETPID` — the process id of the caller (a thread's is its group
/// leader's task id). The one call that does nothing else: it is answered
/// before the dispatch table, so it is the cost of a trap and no more.
///
/// Foundational case 1 (the caller's identity is a kernel fact).
pub const SYS_GETPID: u64 = 10;

/// `DOMAIN_SUBREAPER` op: read the mark.
pub const SUBREAPER_GET: u64 = 0;

/// `DOMAIN_SUBREAPER` op: mark the caller.
pub const SUBREAPER_SET: u64 = 1;

/// `DOMAIN_SUBREAPER` op: clear the mark.
pub const SUBREAPER_CLEAR: u64 = 2;

/// Most live threads of one process (the leader included); see
/// [`SYS_THREAD_CREATE`].
pub const GROUP_THREADS_MAX: u64 = 16;

/// Most processes with more than one live thread at once.
pub const GROUPS_MAX: u64 = 8;

/// `DOMAIN_EXIT_STATS` selector: address spaces torn down on their own task's
/// exit path.
pub const EXIT_STAT_EXIT_TEARDOWNS: u64 = 0;

/// `DOMAIN_EXIT_STATS` selector: address spaces the slot-reuse fallback found
/// still allocated on a slot being claimed (its owner's exit did not release
/// them).
pub const EXIT_STAT_REUSE_TEARDOWNS: u64 = 1;

/// `DOMAIN_EXIT_STATS` selector: exit notices published while the exiting
/// task still held its address space.
pub const EXIT_STAT_EARLY_NOTICES: u64 = 2;

/// `DOMAIN_EXIT_STATS` selector (wave 12, EXIT2): exit notices that found no
/// room and were lost. Zero by construction — notices are kept until reaped,
/// in a table with one entry per task slot behind a creation admission — so
/// any other count is a bug.
pub const EXIT_STAT_NOTICE_DROPS: u64 = 5;

/// `DOMAIN_EXIT_STATS` selector (wave 12, EXIT2): `fork`/`spawn` refusals
/// because queued (unreaped) exit notices hold the task slots that were free.
pub const EXIT_STAT_NOTICE_REFUSALS: u64 = 6;

/// Bytes written by `DOMAIN_TASKINFO`: five `u64`s.
pub const TASKINFO_BYTES: usize = 5 * 8;

/// Largest module `DOMAIN_MODULE_VERIFY` hashes: 4 MiB. Linux's ext4.ko with
/// debug info stripped is about 1 MiB on these ISAs [est.]; the bound keeps
/// one call's kernel time bounded.
pub const MODULE_MAX_BYTES: u64 = 4 << 20;


// ── Time and scheduling ───────────────────────────────────────────────

/// `SYS_YIELD` — give the hart to another ready task of the same or a higher
/// priority. Returns 0. Answered before the dispatch table, like
/// [`SYS_GETPID`].
///
/// Foundational case 2 (block/wake: hands the hart to another task).
pub const SYS_YIELD: u64 = 11;

/// `SYS_SLEEP_UNTIL` — block until an absolute deadline. `a0` =
/// nanoseconds on the RISC-V `time` counter, converted to ticks rounding up
/// (`crate::time::ns_to_ticks_ceil`).
///
/// `0`: the caller blocked and the counter has reached the deadline. `1`: the
/// deadline had already passed at entry; the caller did not block.
///
/// Foundational case 2 (block/wake: sleeps until a deadline).
pub const SYS_SLEEP_UNTIL: u64 = 12;

/// `SYS_SCHEDCTL` (N6b) — `a0` = target tid (0 = the caller; another task is
/// refused with `-EPERM` for now), `a1` = class ([`SCHEDCTL_CLASS_FAIR`],
/// [`SCHEDCTL_CLASS_RT`] or [`SCHEDCTL_CLASS_DL`], the `azos_sched::sc::Class`
/// numbers), `a2` = base priority (fair: `RT_PRIORITY_THRESHOLD..IDLE`;
/// RT and DL: a band level, `< RT_PRIORITY_THRESHOLD`), `a3` = DL runtime
/// per period in µs, `a4` = DL period in µs (the relative deadline is the
/// period), `a5` = a `time` endpoint capability (`endpoint = "time"`). RT and DL need
/// the warrant with `WRITE`, checked FIRST; a refusal is recorded
/// (`SAFETY_CAP_DENIED_TYPED`), so a task cannot promote itself. Fair needs
/// none, but cannot leave the band or a reservation (`-EBUSY`). Returns 0,
/// `-EINVAL` (unknown class, a priority outside the class's range, zero
/// or malformed DL times), `-EPERM`, `-EBUSY` (DL on a task that already
/// holds a reservation, or fair from RT/DL), `-ENOSYS` (the class is
/// compiled out), admission's refusal (`Refusal::errno`: `-EBUSY` no room,
/// `-EACCES` the Domain's `rt_time` envelope row holds it), or the
/// capability's `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS`.
///
/// Foundational case 1 (authority: priority, class and affinity of a task).
pub const SYS_SCHEDCTL: u64 = 13;

/// `SYS_SLEEP_UNTIL` flag (`a1`): `a0` is a duration in nanoseconds from now,
/// not a deadline.
pub const SLEEP_RELATIVE: u64 = 1;

/// [`SYS_SCHEDCTL`] class: deadline (an EDF + CBS reservation).
pub const SCHEDCTL_CLASS_DL: u64 = 1;

/// [`SYS_SCHEDCTL`] class: the fixed-priority RT band.
pub const SCHEDCTL_CLASS_RT: u64 = 2;

/// [`SYS_SCHEDCTL`] class: fair.
pub const SCHEDCTL_CLASS_FAIR: u64 = 3;

/// [`SYS_SCHEDCTL`] hint (not a class): `a1` = this, `a2` = the caller's QoS
/// hint ([`QOS_DEFAULT`]..=[`QOS_BACKGROUND`], 0..=3). Caller only, no warrant
/// (a hint grants nothing; it only says what the task wants), the class and
/// priority are untouched. Returns 0, or `-EINVAL` for a level above 3.
/// Recorded in the task's scheduling context. The timer heap reads it: a fair
/// task's timers may fire late by its tier's slack (Kconfig
/// `QOS_TIMER_TOLERANCE`, `QOS_SLACK_*_US`) and share wake-ups; a real-time
/// or deadline task's never do, whatever it says.
pub const SCHEDCTL_HINT_QOS: u64 = 4;

/// QoS hint: no statement (every task starts here).
pub const QOS_DEFAULT: u32 = 0;

/// QoS hint: latency matters more than throughput (interactive, a control
/// loop that is not real-time).
pub const QOS_LATENCY: u32 = 1;

/// QoS hint: throughput matters more than latency (a batch job).
pub const QOS_THROUGHPUT: u32 = 2;

/// QoS hint: may be delayed for energy (housekeeping, a sync, a poll nobody
/// waits for).
pub const QOS_BACKGROUND: u32 = 3;


// ── Memory ────────────────────────────────────────────────────────────

/// `SYS_MO_CREATE` — creates a MemObj (`azos_ipc::memobj`) of
/// `a0 = page_count` pages and mints a `Cap<Shm>` into the caller's cap-table.
///
/// `a1` is the creation word (the plain values `0` and `1` are the access mode alone):
///
/// | bits    | field                                                              |
/// |---------|--------------------------------------------------------------------|
/// | `1:0`   | access mode: 0 = ReadOnly, 1 = ReadWrite                           |
/// | `15:8`  | kind: [`SHM_KIND_ANON`], or [`SHM_KIND_CONTIG`] (one physical run, for memory a device DMAs; Paged and Phys are the kernel's) |
/// | `23:16` | attributes: [`SHM_ATTR_SWAPPABLE`], [`SHM_ATTR_NO_KERNEL_MAP`], [`SHM_ATTR_VOLATILE`] |
/// | `24`    | [`SHM_CREATE_CLONE`]: make a copy-on-write snapshot of the object the capability in `63:32` names (`READ`); `a0` must then be 0 or the source's page count |
/// | `63:32` | the source capability handle when bit 24 is set, else 0            |
///
/// Any other bit set is `-EINVAL`.
///
/// Returns the raw `CapHandle` as `i64` (positive) on success, or
/// `-Errno` (`ENOMEM`, `EINVAL`, `EMFILE`) on failure. On cap-table
/// exhaustion the region is rolled back so callers never observe a
/// half-created region. The frames are charged to the caller's Domain.
///
/// Foundational case 1 (authority: mints a memory-object capability, frames charged to the domain).
pub const SYS_MO_CREATE: u64 = 14;

/// `SYS_MO_MAP` — map memory into the caller's address space. `a0` names what:
/// a `Cap<Shm>` handle (a region), or 0 (anonymous memory).
///
/// **A region** (`a0` a handle, `a1` 0): maps it with the region's own access
/// mode and returns the base address, or `-Errno`. Requires `READ` and `MAP`; a
/// writable region also requires `WRITE`, which containment refuses (`-EAGAIN`). The
/// mapping is recorded, one per task and region, and [`SYS_MO_UNMAP`] removes
/// it before it gives back the caller's references. In order: `-ECAPSTALE` /
/// `-ECAPKIND` / `-ECAPPERMS` / `-EAGAIN` for the capability; `-EINVAL` for a
/// kernel caller; `-EBUSY` when the caller already maps the region; `-EBADF`
/// when the region has no room for another holder; `-EPURGED` when the region
/// was created volatile ([`SHM_ATTR_VOLATILE`]) and reclaim took its frames;
/// `-ENOMEM` when the pages could not be mapped (the reference is kept then,
/// until the caller exits).
/// With [`SHM_MAP_OP_PROTECT`] in `a1`: the protect form.
///
/// **Anonymous memory** (`a0` 0): `a1` the address hint (ignored: the range is
/// placed at the break), `a2` the length (capped at
/// `azos_mm::demand::MAX_DEMAND_ALLOC_BYTES`), `a3` the protection
/// (`PROT_READ` 1, `PROT_WRITE` 2, 0 reserves the range and maps nothing;
/// `PROT_EXEC` is refused with `-EINVAL`: W^X holds for ring 3 by
/// construction), `a4` the flags (ignored). Returns the address, or `-1`.
///
/// A handle that is not memory is `-ECAPKIND`.
///
/// Foundational case 1 (protection: only the kernel edits the page tables).
pub const SYS_MO_MAP: u64 = 15;

/// `SYS_MO_UNMAP` — `a0` names what goes: a `Cap<Shm>` handle, or 0.
///
/// **A region** (`a0` a handle): removes the caller's mapping of it, then
/// gives back every reference the caller holds on it (the creation
/// reference, the acquire op's and [`SYS_MO_MAP`]'s); frees all backing pages
/// when no task holds one. Requires `READ`. The cap **is revoked** by the same
/// call, so the references go with it; one that a failed [`SYS_MO_MAP`] kept
/// stays until the caller exits. `-EBADF` when the caller holds no reference.
///
/// **Anonymous memory** (`a0` 0): `a1` the address, `a2` the length of the
/// range to unmap (page-rounded, in the user half, at most
/// `azos_mm::demand::MAX_DEMAND_ALLOC_BYTES`). `-1` for a range it refuses.
///
/// A handle that is not memory is `-ECAPKIND`.
///
/// Foundational case 1 (protection: only the kernel edits the page tables).
pub const SYS_MO_UNMAP: u64 = 16;

/// [`SYS_MO_CREATE`] creation word: shift of the kind field.
pub const SHM_CREATE_KIND_SHIFT: u32 = 8;

/// [`SYS_MO_CREATE`] creation word: shift of the attribute field.
pub const SHM_CREATE_ATTR_SHIFT: u32 = 16;

/// [`SYS_MO_CREATE`] creation word: clone the object named in bits 63:32.
pub const SHM_CREATE_CLONE: u64 = 1 << 24;

/// [`SYS_MO_CREATE`] creation word: shift of the source capability.
pub const SHM_CREATE_SRC_SHIFT: u32 = 32;

/// MemObj kind: zero-filled anonymous frames.
pub const SHM_KIND_ANON: u64 = 0;

/// MemObj kind: zero-filled frames in one physically contiguous run, charged to
/// the creator's Domain like an Anon object's, and visible to a device. What a
/// stream's arena is made of (`azos_devif::sound`, `azos_devif::display`): the
/// kernel then has one bus address for it. Fails with `-ENOMEM` when no run of
/// that length is free, which is why a client makes its arena once, early.
/// Not with [`SHM_ATTR_VOLATILE`] or [`SHM_ATTR_SWAPPABLE`] (`-EINVAL`).
pub const SHM_KIND_CONTIG: u64 = 2;

/// MemObj attribute: the reclaimer may take the frames (stored; no reclaimer yet).
pub const SHM_ATTR_SWAPPABLE: u64 = 1;

/// MemObj attribute: the kernel never reads the object through the direct map
/// (so a `notify` word cannot live in it).
pub const SHM_ATTR_NO_KERNEL_MAP: u64 = 2;

/// MemObj attribute: purgeable. The owner marks the object droppable with the
/// kernel-hosted `MemCtl` interface; under memory pressure the kernel then
/// takes its frames whole, without writing them, and a later [`SYS_MO_MAP`]
/// answers `-EPURGED`. Anon objects only.
pub const SHM_ATTR_VOLATILE: u64 = 4;

/// [`SYS_MO_MAP`] `a1` flag: the protect form. Instead of mapping, change
/// the access of the caller's mapping of the object the capability (`READ`)
/// names: read-only, or with [`SHM_MAP_PROT_WRITE`] writable again, never past
/// what the map was allowed (`-ECAPPERMS`), nor while the object has frames a
/// clone shares (`-ECAPPERMS`, `-EBUSY`).
/// `-EBADF` when the caller has no mapping of it. `a1 = 0` maps.
pub const SHM_MAP_OP_PROTECT: u64 = 1 << 8;

/// [`SHM_MAP_OP_PROTECT`]: the mapping is to be writable.
pub const SHM_MAP_PROT_WRITE: u64 = 1;

// ── IPC ───────────────────────────────────────────────────────────────

/// `SYS_IPC_FAST_CALL_EP` — the fast call, addressed by a **capability**.
/// `a0` = a `Cap<Endpoint>` handle, `a1..a4` = the four
/// message words, `a5` = a capability to move with the request (0 for none).
/// With [`FAST_CALL_CAP_SHARE`] set in `a5` the capability is SHARED instead:
/// the receiver gets a derived copy (the sender's rights, a child of its
/// warrant) and the sender keeps its own handle — and, for a `Cap<Shm>`, its
/// mapping. A MOVE of a `Cap<Shm>` takes the sender's mapping with it.
///
/// `a0` is resolved through the caller's own capability table, demanding
/// `WRITE` on a `Cap<Endpoint>`; the request is queued on that endpoint and
/// the task serving it is woken. A caller holding no endpoint capability can
/// reach nothing. The raw-TID form is retired (wave 15 N5): the
/// endpoint is the only address.
///
/// The resolution is `cap_store::get`, so it is also refused while
/// degraded mode is armed: a contained task may still report on the console,
/// but it may not open new service requests.
///
/// Returns reply word 0 in `a0` (words 1..3 in `a1..a3`), or a negative code:
/// `-1` when the capability does not resolve, carries no `WRITE`, names an
/// endpoint no task serves yet (one code on purpose: which of them it was
/// tells a caller about capabilities it does not hold), or the call was given
/// up without an answer; and the completion codes of `error::Errno`
/// `EPEERDIED` (the serving task died with the call queued or in service),
/// `EREVOKED` (the endpoint was destroyed while the call was queued or in
/// service). A proxy endpoint (a service on another node) reports a lost link in
/// the reply, `azos_idl::IdlError::NoConnection`, not as a code here.
///
/// **`SYS_IPC_FAST_REPLY_ACCEPT` is not a TID call**: it answers the
/// exchange in hand and then blocks for the next request on the caller's own
/// endpoints. It is the server side of the loop `vsbench` runs on the hot
/// path.
///
/// Foundational case 2 (block/wake: the caller sleeps until the server replies).
pub const SYS_IPC_FAST_CALL_EP: u64 = 19;

/// `SYS_IPC_FAST_REPLY` — a server answers an exchange in hand: `a0` = the
/// handle from the accept, `a1..a4` = the four reply words. Returns 0
/// delivered, `-2` for a stale handle, `-1` for any other refusal.
///
/// Foundational case 2 (block/wake: wakes the caller of the exchange).
pub const SYS_IPC_FAST_REPLY: u64 = 18;

/// `SYS_IPC_FAST_ACCEPT` — a server takes the next request on an endpoint it
/// serves, blocking (up to eight wakes). `a0` = the handle of the exchange
/// (the reply warrant's name), `a1` = the caller's task id, `a2..a5` = the
/// four request words (and `a6` the server's handle of the capability the
/// request moved, or a sentinel when it moved none); `-1` when nothing arrived.
///
/// Foundational case 2 (block/wake: the server sleeps until a call arrives).
pub const SYS_IPC_FAST_ACCEPT: u64 = 20;

/// `SYS_IPC_FAST_REPLY_ACCEPT` — a server's reply and its next accept in one
/// trap. `a0` = the handle from the previous accept, `a2..a5` =
/// the four reply words. `a1` is not read: libsys preloads the accept's
/// not-written sentinel there.
///
/// Fail-fast (owner decision 2026-09-15). A reply that is not delivered
/// accepts nothing and returns at once: `-2` for a stale handle, `-3` for any
/// other refusal. A delivered reply continues exactly as `SYS_IPC_FAST_ACCEPT`:
/// `a0` = the next handle with `a1` = caller TID and `a2..a5` = its words, or
/// `-1` when nothing arrived within the accept's eight wakes.
///
/// Foundational case 2 (block/wake: reply, then sleep for the next call).
pub const SYS_IPC_FAST_REPLY_ACCEPT: u64 = 17;

/// `SYS_IPC_CALL_V2` — `a0 = Cap<Endpoint>` (`WRITE`), `a1 = *mut MsgDesc`.
/// The v2 call: up to the kernel's Kconfig `IPC_MSG_INLINE_WORDS` inline
/// words and `IPC_MSG_MAX_CAPS` capability entries, moved to the serving
/// task all or nothing (`MSG_KEEP` keeps the MOVE entries on a refusal),
/// with the badge of the capability in `a0` recorded for the server. Blocks
/// until the call is answered; the answer is written over `*a1` (its words,
/// the receiver's handles of the capabilities the reply moved, `n_words`,
/// `n_caps`). Returns 0 when answered; `-EPEERDIED` / `-EREVOKED` when the
/// call completed without an answer; `-EV1ACCEPT` when the server took it
/// with the v1 accept (`SYS_IPC_FAST_ACCEPT` or
/// `SYS_IPC_FAST_REPLY_ACCEPT`): the kernel refuses the call there, the
/// server sees nothing, and every capability the call carried is back in
/// the caller's table (owner decision 10-10; a v1 accept names only four
/// words and one capability, so the rest would sit unnamed in the server's
/// table); `-EINVAL` for a descriptor the kernel
/// refuses (version, counts above its limits, a mode other than MOVE/DUP,
/// non-zero `flags` bits other than `MSG_KEEP`, a `label` with a reserved bit, or a
/// `clock_id` other than `ClockId::MONO`, the one clock served);
/// `-EDEADLINE` when the descriptor's `deadline`
/// (absolute ns on `MONO`, 0 = none) is at or before now: refused before the
/// call is queued, nothing moved, one `deadline-expired` decision record; the
/// server reads the same `deadline` and `clock_id` in the descriptor it
/// accepts; `-EADMIT` when the deadline is one the server's scheduling context
/// cannot meet (its reservation's relative deadline is longer than the time
/// left, or its per-call budget does not fit the time or the budget the
/// caller's own reservation has left): refused before the call is queued,
/// nothing moved, one `call-admission` record, and `*a1` holds the
/// counter-offer (`words[0]` the record's id, the receipt; `words[1]` 1 for a
/// deadline, 2 for a budget; `words[2]` the offered deadline in ns or budget
/// in us; `deadline` the offered deadline); a call with a deadline lends the
/// caller to its server (a passive server runs on the caller's reservation);
/// `-ERTPROXY` when the caller is a real-time task and the endpoint a
/// proxy (the topology names it `endpoint.rpc-<service>`: a service on another
/// node), refused before the call is queued, one `cap-denial` record;
/// `-EFAULT`; -1 (`E_PERM`)
/// for the capability or a refused transfer, one code as for `SYS_IPC_FAST_CALL_EP`; -1 also
/// when the wait ran out (the call is withdrawn).
///
/// Foundational case 2 (block/wake), and 1 when the message moves capabilities.
pub const SYS_IPC_CALL_V2: u64 = 21;

/// `SYS_IPC_ACCEPT_V2` — `a0 = *mut MsgDesc`. The accept of
/// `SYS_IPC_FAST_ACCEPT` (same queue, same blocking), writing the request into `*a0`: for a v2 call its
/// words, the server's handles of the moved capabilities, the badge, and
/// `MSG_BADGED`; for a v1 call (`SYS_IPC_FAST_CALL_EP`) its four words, its moved capability
/// (if any) as one entry, and no `MSG_BADGED`. Returns the call's handle
/// (the reply warrant's name, `>= 0`), -1 when nothing arrived, `-EFAULT`
/// (the call stays accepted: answer or delegate it by the returned handle).
/// Writes no register but `a0`.
///
/// Foundational case 2 (block/wake: the server sleeps until a call arrives).
pub const SYS_IPC_ACCEPT_V2: u64 = 22;

/// `SYS_IPC_REPLY_V2` — `a0` = call handle, `a1 = *const MsgDesc`. Answer
/// as the holder of the call's reply warrant, once. The reply's words go to
/// the caller and its capability entries move to the caller's table all or
/// nothing, before the answer is published. To a v1 call only the first
/// four words travel and no capability may (`-EINVAL`). Returns 0; -3 when
/// the caller does not hold the warrant of an unanswered call (checked
/// first, so a call already over also reads -3 here); -2 when the call
/// ended between that check and the answer (the moved capabilities go
/// back); `-EINVAL`, `-EFAULT`, -1 for a refused transfer.
///
/// Foundational case 2 (block/wake), and 1 when the reply moves capabilities.
pub const SYS_IPC_REPLY_V2: u64 = 23;

/// `SYS_IPC_REPLY_DELEGATE` — `a0` = call handle, `a1` = TID of a thread of
/// the caller's own process. Move the reply warrant: from then on only that
/// thread may answer (`SYS_IPC_FAST_REPLY`, `SYS_IPC_FAST_REPLY_ACCEPT` or
/// `SYS_IPC_REPLY_V2`), once. Returns 0, -2 when the call is
/// over, -3 when the caller does not hold the warrant, `-EPERM` when `a1`
/// is not a live thread of the caller's process (a warrant addressed to
/// another process is the warrant foundation's, not this call's).
///
/// Foundational case 2 (block/wake: hands the pending caller to another server), and 1 (authority over the exchange).
pub const SYS_IPC_REPLY_DELEGATE: u64 = 24;

/// `SYS_RING_SETUP` — allocates an io_ring and mints a
/// `Cap<IoRing>` into the caller's cap-table.
///
/// `a0 = out_ptr` (8 bytes, `u64 LE`): ring 3 receives the user address
/// of the ring page, mapped user RW and never executable in the task's
/// shm/MMIO window and unmapped by [`SYS_CAP_CLOSE`]; a kernel
/// caller receives the physical address.
///
/// Returns the raw `CapHandle` as `i64` (positive) on success, or
/// `-Errno` (`ENOMEM`, also when the page cannot be mapped; `EMFILE`,
/// `EFAULT`). On cap-table exhaustion the ring is rolled back so callers
/// never observe a half-created ring.
///
/// Foundational case 1 (protection: maps the shared ring into the caller and the kernel).
pub const SYS_RING_SETUP: u64 = 25;

/// `SYS_RING_ENTER` — process SQEs on the ring referenced
/// by `a0 = cap_handle`. Returns the number of SQEs processed
/// (`u32`, sign-extended into `i64` ≥ 0) or `-Errno`. Requires
/// `WRITE` on the cap.
///
/// Each entry is checked against the submitter's seccomp profile (the call
/// the entry stands for), the owner's capability and, for a write,
/// containment, and runs through the same function the matching op runs. A
/// refused entry completes with `IORING_CQE_F_REFUSED` set and `-Errno` in
/// `result`. `-EBUSY` when an entry is pending and the completion queue is
/// full: nothing ran, and `sq_head` still names that entry.
///
/// Foundational case 2 (block/wake: sleeps for completions or kicks the kernel side).
pub const SYS_RING_ENTER: u64 = 26;

/// `SYS_PORT_WAIT` — wait on an event port: `a0` the port handle (`READ`), `a1`
/// a user buffer of 16 bytes for the event, `a2` the deadline, absolute
/// nanoseconds on the time counter (`u64::MAX`: none; an instant already
/// passed polls). Returns 16 with the event written, 0 when the deadline passed
/// with nothing ready (the buffer is untouched), or a negative errno:
/// `-EINVAL` (null buffer), the handle's `-ECAPSTALE` / `-ECAPKIND` /
/// `-ECAPPERMS`, `-EFAULT` (checked before anything is dequeued), `-ECAPSTALE`
/// when the port is destroyed during the wait, `-EMFILE` when the port has its
/// maximum number of waiters, `-EBUSY` when the scheduler refused to block.
///
/// Foundational case 2 (block/wake: sleeps until a port event).
pub const SYS_PORT_WAIT: u64 = 27;

/// [`SYS_IPC_FAST_CALL_EP`] `a5` flag (bit 32): share the capability in the low
/// 32 bits instead of moving it.
pub const FAST_CALL_CAP_SHARE: u64 = 1 << 32;

/// `CqEntry.flags` bit: the kernel refused the entry, and `result` holds
/// `-Errno`. Mirrors `azos_ipc::io_ring::CQE_F_REFUSED`.
pub const IORING_CQE_F_REFUSED: u32 = 1;

/// the port bind op (`PORT_BIND`) flag in `a1`: remove the sources of the type in
/// the low byte bound with the key in `a3`, instead of binding one.
pub const PORT_BIND_F_REMOVE: u64 = 0x100;

/// Port source: an io_ring (`Cap<IoRing>` with `READ`).
pub const PORT_SRC_RING: u64 = 1;

/// Port source: a timer (the source word is an absolute deadline in ns).
pub const PORT_SRC_TIMER: u64 = 2;

/// Port source: an endpoint's notices (`Cap<Endpoint>` with `READ`, held by
/// the endpoint's serving task). Reports [`PORT_EVENT_NO_SENDERS`].
pub const PORT_SRC_ENDPOINT: u64 = 3;

/// Port source: the calling Domain's own frame-budget pressure (the source
/// word is `DOMAIN_SELF`). Reports [`PORT_EVENT_PRESSURE`] on every change of
/// level, from the high watermark on, before the reclaim task compresses
/// anything of the Domain. One Port per Domain: a second bind replaces the
/// first, and removing the type unbinds it.
pub const PORT_SRC_PRESSURE: u64 = 4;

/// Event source type: an io_ring has completions.
pub const PORT_EVENT_RING: u8 = 2;

/// Event source type: an IRQ was delivered (`DEVICE_IRQ_BIND`).
pub const PORT_EVENT_IRQ: u8 = 3;

/// Event source type: a timer fired.
pub const PORT_EVENT_TIMER: u8 = 4;

/// Event source type: no send capability to the bound endpoint is left
/// anywhere (a `Cap<Endpoint>` with `WRITE` and without `READ`); the event's
/// code is `ENOSENDERS`. Level at bind: binding an endpoint that has no
/// sender reports one at once.
pub const PORT_EVENT_NO_SENDERS: u8 = 5;

/// Event source type: the bound source is gone (destroyed, or its owner
/// died) and its binding was removed; the event's key and `source_id` are
/// the binding's, and its code is `EREVOKED` (destroyed) or `EPEERDIED` (its
/// owner died). Delivered once; the source's slot is free after it.
pub const PORT_EVENT_SOURCE_GONE: u8 = 6;

/// Event source type: the Domain's frame budget changed level
/// ([`PORT_SRC_PRESSURE`]). The event's `source_id` is the new level (0
/// normal, 1 warning: reclaim is due, 2 critical: the limit is reached), its
/// key the one the source was bound with, its code 0. Edge-triggered: one event
/// per change, and a queue that is full drops the newest.
pub const PORT_EVENT_PRESSURE: u8 = 7;

/// Byte offset of the event's code (`u16`, little-endian; a positive errno,
/// 0 for an ordinary event) in the 16-byte port event. Bytes 12..16 are
/// `source_id`.
pub const PORT_EVENT_CODE_OFFSET: usize = 10;

/// Byte offset of the event's CPU (`u8`) in the 16-byte port event: for a
/// [`PORT_EVENT_IRQ`] event the CPU the line is routed to (where the interrupt
/// was taken and, for a handler pinned there, where it is woken), 0 for every
/// other event.
pub const PORT_EVENT_CPU_OFFSET: usize = 9;


// ── Futex ─────────────────────────────────────────────────────────────

/// `SYS_FUTEX_WAIT` — wave 13: `a0` = address of an aligned 32-bit word,
/// `a1` = the value it must hold, `a2` = a relative timeout in nanoseconds
/// (0: none). Blocks while the word holds `a1` until a [`SYS_FUTEX_WAKE`]
/// on the same word, the timeout, or a stop. The word is keyed by the
/// shared-memory region the caller maps it from and its offset there, so
/// tasks that map the region at different addresses (the two sides of a
/// shared ring) meet on it; any other word is keyed by the calling
/// process, so only its threads meet on it. Returns 0 (woken), `-EAGAIN`
/// (the word differs), `-ETIMEDOUT` (110), `-EINTR`, `-EFAULT`, `-EINVAL`
/// (misaligned).
///
/// Foundational case 2 (block/wake: sleeps on a word).
pub const SYS_FUTEX_WAIT: u64 = 28;

/// `SYS_FUTEX_WAKE` — wave 13: wake at most `a1` waiters on the word at `a0`,
/// keyed as [`SYS_FUTEX_WAIT`] keys it. Returns how many were woken;
/// `-EFAULT` for a word the caller cannot read, `-EINVAL` misaligned.
///
/// Foundational case 2 (block/wake: wakes the sleepers of a word).
pub const SYS_FUTEX_WAKE: u64 = 29;


// ── Foreign ABI ───────────────────────────────────────────────────────

/// `SYS_FOREIGN_ENTRY` — D6 "foreign ABI" family (see `crate::foreign`).
/// `a0` = the user address of the runtime's trap entry, `a1` = flags (must be
/// 0). Registers the calling thread's entry for reflected traps and leaves it
/// in runtime mode; a later [`SYS_FOREIGN_RESUME`] puts it in foreign mode.
/// `a0` = 0 withdraws the registration. Returns 0, `-EINVAL` (flags not 0, or
/// an entry that is not a user address), `-ENOSYS` (kernel built without
/// Kconfig `LINUX_ABI`, whose per-CPU syscall word the mode bit shares).
///
/// Foundational case 1 (authority: registers a trap reflection for the thread).
pub const SYS_FOREIGN_ENTRY: u64 = 30;

/// `SYS_FOREIGN_RESUME` — D6 "foreign ABI" family. `a0` = the user address of a
/// `crate::foreign::ForeignFrame`. Restores every register in it (the flags
/// word only in `crate::foreign::FLAGS_USER_MASK`), puts the thread in foreign
/// mode and returns to user mode at the frame's program counter. Does not
/// return to its caller on success; `-EFAULT` (frame unreadable) and `-EINVAL`
/// (no entry registered, or the frame names a program counter outside user
/// space) leave the thread in runtime mode.
///
/// Foundational case 1 (protection: only the kernel installs a full register frame).
pub const SYS_FOREIGN_RESUME: u64 = 31;


// ── Generic ───────────────────────────────────────────────────────────

/// `SYS_INVOKE` — D6: every operation on an object the caller holds a handle to
/// (`a0`), selected by the op word (`a1`) in the namespace of the handle's
/// type. The wire format, the two forms and the self handles are
/// `crate::invoke`.
///
/// Foundational case 1 (authority: every op is checked against the held handle); device and cross-space ops are counted under it too.
pub const SYS_INVOKE: u64 = 32;

/// `SYS_FOREIGN_FORK` — the foreign-ABI family's process copy: a copy-on-write
/// copy of the calling process for a ring-3 runtime that hosts a foreign
/// program's `fork`. The child resumes at the instruction after this call with
/// a result of 0; the caller gets the child's task id. The child holds the
/// caller's descriptors and pipe regions at the same handles (sharing the open
/// description) and the capabilities of its own topology row, never a copy of
/// the caller's table. Refused with `-EPERM` unless the caller has registered
/// a foreign entry ([`SYS_FOREIGN_ENTRY`]): a native program has no fork, its
/// creation call is [`SYS_SPAWN_EX`]. Returns `-EAGAIN` when the copy cannot be
/// made, `-ENOSYS` in a kernel built without Kconfig `LINUX_ABI`.
///
/// Foundational case 1 (protection: copies an address space).
pub const SYS_FOREIGN_FORK: u64 = 33;

/// Bytes the stat op of the domain (`DOMAIN_STAT`) writes to its buffer: all little-endian,
/// at these offsets. The caller's buffer must be at least this long.
///
/// | off | type | field |
/// |---|---|---|
/// | 0 | u64 | size in bytes |
/// | 8 | u32 | mode: `S_IF*` type bits and `0o7777` permissions |
/// | 12 | u32 | nlink |
/// | 16 | u32 | uid |
/// | 20 | u32 | gid |
/// | 24 | u64 | atime, seconds since the Unix epoch (0: not kept) |
/// | 32 | u64 | mtime |
/// | 40 | u64 | ctime |
/// | 48 | u64 | reserved, 0 |
/// | 56 | u64 | reserved, 0 |
pub const STAT_BYTES: usize = 64;

pub const STAT_OFF_SIZE: usize = 0;

pub const STAT_OFF_MODE: usize = 8;

pub const STAT_OFF_NLINK: usize = 12;

pub const STAT_OFF_UID: usize = 16;

pub const STAT_OFF_GID: usize = 20;

pub const STAT_OFF_ATIME: usize = 24;

pub const STAT_OFF_MTIME: usize = 32;

pub const STAT_OFF_CTIME: usize = 40;

/// `S_IFMT` and the two types a caller most often tests for.
pub const STAT_S_IFMT: u32 = 0o170000;

pub const STAT_S_IFDIR: u32 = 0o040000;

pub const STAT_S_IFREG: u32 = 0o100000;

/// Bytes the readdir op of the domain (`DOMAIN_READDIR`) writes into its name buffer — **always exactly this
/// many**, zero-padding a short name.
///
/// Lives here rather than in `libsys` so the kernel and userspace read ONE
/// definition. It used to exist only on the userspace side, which meant the
/// kernel wrote 64 bytes because a constant it could not see said so.
pub const READDIR_NAME_BYTES: usize = 64;

/// Bytes the statfs op of the domain (`DOMAIN_STATFS`) writes: all little-endian, at these offsets. A shorter
/// buffer is refused with `-EINVAL` and nothing is written.
///
/// | off | type | field |
/// |---|---|---|
/// | 0 | u32 | filesystem type (`1` FAT32, `2` tmpfs, `4` azvol, `0` the ramfs) |
/// | 4 | u32 | block size in bytes (FAT32: the cluster) |
/// | 8 | u64 | blocks |
/// | 16 | u64 | free blocks |
/// | 24 | u64 | files (0: no inode table to count) |
/// | 32 | u64 | free files |
/// | 40 | u32 | longest name in bytes |
/// | 44 | u32 | reserved, 0 |
pub const STATFS_BYTES: usize = 48;

pub const STATFS_OFF_TYPE: usize = 0;

pub const STATFS_OFF_BSIZE: usize = 4;

pub const STATFS_OFF_BLOCKS: usize = 8;

pub const STATFS_OFF_BFREE: usize = 16;

pub const STATFS_OFF_FILES: usize = 24;

pub const STATFS_OFF_FFREE: usize = 32;

pub const STATFS_OFF_NAMEMAX: usize = 40;

// ── The Cap<T> families, as a set ────────────────────────────────────────

/// Every syscall of the table that takes a handle in `a0` (or in `a5`, for
/// [`SYS_SCHEDCTL`]'s warrant) or mints one.
///
/// **Membership is the call, not a number range.** [`SYS_CAP_INFO`],
/// [`SYS_CAP_CLOSE`], [`SYS_CAP_DERIVE`] and [`SYS_CAP_REVOKE`] are the handle
/// family itself and are not listed: they are how a task finds, ends and
/// derives the handles the members take.
///
/// **Members are not uniform**, and a reader deciding policy from this list
/// must know it. Most consume a handle, and are therefore *narrower* than a
/// call that names its object. Two MINT one instead of consuming one —
/// [`SYS_MO_CREATE`] and [`SYS_RING_SETUP`] — and are in the set precisely so a
/// rule cannot skip them by accident: granting a minter to a sandbox profile
/// hands it the power to create authority. [`SYS_MO_MAP`] and [`SYS_MO_UNMAP`]
/// take a handle or 0 (anonymous memory).
///
/// The consumer today is `tests/host/seccomp-tests`: no role profile may grant
/// a member (image rows list what their binary issues, derived from its
/// source). Kept here rather than there because it is an ABI fact — which
/// calls take capabilities — and because syscall numbers live only in this
/// file (gate check `syscall-number literals`).
pub const CAP_TYPED_SYSCALLS: &[u64] = &[
    SYS_PORT_WAIT,
    SYS_MO_CREATE,
    SYS_MO_UNMAP,
    SYS_RING_SETUP,
    SYS_RING_ENTER,
    SYS_MO_MAP,
    SYS_IPC_FAST_CALL_EP,
    SYS_IPC_CALL_V2,
    SYS_SCHEDCTL,
];

/// Reserved upper bound: the table's length. Numbers `>=` this are unassigned
/// and answer `-1`. A call added to the table is added at the end and moves
/// this.
pub const SYS_NR_RESERVED_UPPER: u64 = 34;

// ── The foundational case of each call ──────────────────────────────────────
//
// A call is a syscall only because one of two things cannot be done in ring 3:
// change authority or protection (the handle table, the page tables, a
// protection domain are kernel state), or block and wake (hand the hart to
// another task). Device access and copies between address spaces are ops of
// `SYS_INVOKE`, so they are counted under its case (authority); a finer count
// would have to decode the op in the prologue, and nothing asks for it.
//
// The case is data here, next to the number, so the trap layer
// (`kernel/src/trap`) can count entries by case per Domain without parsing a
// doc comment. It is a table by number, not bits of the number: the dispatch
// table, the filter bitmap and the lean entries' IPC range test all index by
// the number. `tools/trap_lint.py` refuses a `SYS_*` number that has no row
// below.

/// Case 1: authority or protection.
pub const CASE_AUTHORITY: u8 = 1;
/// Case 2: block or wake.
pub const CASE_BLOCK_WAKE: u8 = 2;
/// Number of cases; a case is `1..=CASES`, `0` is "no case" (an unassigned
/// number, or a number of the Linux personality).
pub const CASES: usize = 2;

/// The case of each assigned number, by number; `0` is a hole (number 0 and
/// any number the table does not assign). A call with two cases (the v2 IPC
/// calls move capabilities, `SYS_INVOKE` has ops of both) is listed under the
/// first its doc names: the case that makes it a syscall at all.
pub const SYSCALL_CASE: [u8; SYS_NR_RESERVED_UPPER as usize] = {
    let mut t = [0u8; SYS_NR_RESERVED_UPPER as usize];
    t[SYS_CAP_INFO as usize] = CASE_AUTHORITY;
    t[SYS_CAP_CLOSE as usize] = CASE_AUTHORITY;
    t[SYS_CAP_DERIVE as usize] = CASE_AUTHORITY;
    t[SYS_CAP_REVOKE as usize] = CASE_AUTHORITY;
    t[SYS_SPAWN_EX as usize] = CASE_AUTHORITY;
    t[SYS_THREAD_CREATE as usize] = CASE_AUTHORITY;
    t[SYS_THREAD_EXIT as usize] = CASE_AUTHORITY;
    t[SYS_EXIT as usize] = CASE_AUTHORITY;
    t[SYS_ALERT as usize] = CASE_AUTHORITY;
    t[SYS_GETPID as usize] = CASE_AUTHORITY;
    t[SYS_YIELD as usize] = CASE_BLOCK_WAKE;
    t[SYS_SLEEP_UNTIL as usize] = CASE_BLOCK_WAKE;
    t[SYS_SCHEDCTL as usize] = CASE_AUTHORITY;
    t[SYS_MO_CREATE as usize] = CASE_AUTHORITY;
    t[SYS_MO_MAP as usize] = CASE_AUTHORITY;
    t[SYS_MO_UNMAP as usize] = CASE_AUTHORITY;
    t[SYS_IPC_FAST_REPLY_ACCEPT as usize] = CASE_BLOCK_WAKE;
    t[SYS_IPC_FAST_REPLY as usize] = CASE_BLOCK_WAKE;
    t[SYS_IPC_FAST_CALL_EP as usize] = CASE_BLOCK_WAKE;
    t[SYS_IPC_FAST_ACCEPT as usize] = CASE_BLOCK_WAKE;
    t[SYS_IPC_CALL_V2 as usize] = CASE_BLOCK_WAKE;
    t[SYS_IPC_ACCEPT_V2 as usize] = CASE_BLOCK_WAKE;
    t[SYS_IPC_REPLY_V2 as usize] = CASE_BLOCK_WAKE;
    t[SYS_IPC_REPLY_DELEGATE as usize] = CASE_BLOCK_WAKE;
    t[SYS_RING_SETUP as usize] = CASE_AUTHORITY;
    t[SYS_RING_ENTER as usize] = CASE_BLOCK_WAKE;
    t[SYS_PORT_WAIT as usize] = CASE_BLOCK_WAKE;
    t[SYS_FUTEX_WAIT as usize] = CASE_BLOCK_WAKE;
    t[SYS_FUTEX_WAKE as usize] = CASE_BLOCK_WAKE;
    t[SYS_FOREIGN_ENTRY as usize] = CASE_AUTHORITY;
    t[SYS_FOREIGN_RESUME as usize] = CASE_AUTHORITY;
    t[SYS_INVOKE as usize] = CASE_AUTHORITY;
    t[SYS_FOREIGN_FORK as usize] = CASE_AUTHORITY;
    t
};

/// The foundational case (`1..=CASES`) of native number `nr`, or `0` for a
/// number the table does not assign.
#[inline(always)]
pub const fn syscall_case(nr: u64) -> u8 {
    if nr < SYS_NR_RESERVED_UPPER { SYSCALL_CASE[nr as usize] } else { 0 }
}

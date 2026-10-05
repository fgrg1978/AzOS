// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Frozen syscall numbers.
//!
//! These are the **canonical** definitions from W1 onwards. `crates/core/syscall`
//! (`crates/core/syscall/src/numbers.rs`) re-exports this module verbatim rather
//! than restating it, and `crates/core/libsys` imports the names it needs from
//! here directly — neither crate keeps an independent copy of a number.
//!
//! Within ABI v1, no number can move and no new number is added without an
//! RFC.
//!
//! ## Number-space conventions
//!
//! | Range     | Subsystem                            |
//! |-----------|--------------------------------------|
//! | 0..=19    | Process control                      |
//! | 20..=29   | File I/O (basic)                     |
//! | 100..=119 | IPC (channels, fast-path, lease, SHM)|
//! | 200..=229 | GPIO / PWM / I2C                     |
//! | 230..=249 | Motor + system info                  |
//! | 250..=269 | Filesystem + network                 |
//! | 270..=299 | System control / disk / FDT          |
//! | 300..=319 | Driver-server (E11.AQ3)              |
//! | 320..=349 | Robot control + platform             |
//! | 350..=369 | Signals + pipes                      |
//! | 370..=389 | Sockets                              |
//! | 390..=399 | Service manager                      |
//! | 400..=429 | Memory mgmt + ADC + buzzer           |
//! | 430..=499 | Security (seccomp, future)           |
//! | 500..=529 | IO ring, channels, MMIO/IRQ, ports, handles, trace, drivers |
//! | 528..=579 | `Cap<T>` typed calls (RFC-0003); 573..=578 the gap-1 typed forms (RFC-0040) |
//!
//! A retired number is never reused: see [`RETIRED_SYSCALLS`].
//!
//! ## Register convention (per ISA)
//!
//! The numbers above are ISA-independent — `SYS_GETPID` is `10` on every
//! target this ABI reaches. Which *registers* carry the number, the
//! arguments and the result is a per-ISA convention, established here (phase
//! 6 prep, aarch64 parity) so the kernel side (`kernel/**`,
//! `crates/core/arch-aarch64/**`) implements exactly this rather than inventing
//! its own mapping. **No kernel-side aarch64 syscall dispatch exists yet —
//! this is documentation for the implementation to follow, not a claim that
//! it does.**
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
//! Trap instruction: `ecall`. The fast-IPC family (`SYS_IPC_FAST_CALL` and
//! kin) is the only one that uses `a6` — every other syscall's kernel-written
//! output is `a0` alone, and a wrapper that does not declare every register
//! the kernel writes as `lateout`/`inlateout` invites the exact class of bug
//! `crates/core/libsys/src/lib.rs` documents on `trace_dump` and the fast-IPC
//! functions: an `asm!` that leaves a result register `in`-only lets rustc
//! assume it survives the trap, and the kernel overwriting it is then
//! undefined behaviour, not a wrong answer.
//!
//! ### AArch64 (this section — `aarch64-unknown-none`, hard-float,
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
//! nothing in either direction and is available to the kernel as scratch
//! without being declared clobbered by any wrapper.
//!
//! ### What the kernel (phase 6) must preserve
//!
//! Same rule stated for the register set that applies to it:
//!
//!   * A syscall that returns only `x0` must leave `x1..=x7` and every
//!     other GPR (`x9..=x30`; `x8` is post-trap scratch, freely clobbered)
//!     exactly as the caller left them. `SyscallOut`-style arms (the
//!     fast-IPC family) may additionally write `x1..=x6`, and MUST write
//!     every one of them on every path — success and failure alike —
//!     because a caller that declares them `lateout` (not `inlateout`) is
//!     entitled to assume the trap clobbers them regardless of outcome; an
//!     arm that writes them only on success reproduces the `trace_dump` bug
//!     `crates/core/libsys` already found and fixed on the RISC-V side.
//!   * `SP_EL0` must be 16-byte aligned at every `_start` entry. Unlike
//!     RISC-V (no stack-alignment trap), `SCTLR_EL1.SA0` — if the kernel
//!     enables it — faults a misaligned `sp` on the very first stack access
//!     in EL0, before any user code runs. The userspace linker scripts in
//!     `userspace/**` page-align every writable segment already (W^X); stack
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
//!     needs `CNTKCTL_EL1.EL0VCTEN` set for EL0 to read it without trapping
//!     — the same "native vs. must-trap" distinction
//!     `vdso_rdtime_native`/`VDSO_FLAG_RDTIME_NATIVE` already carries for
//!     RISC-V's `time` CSR. No aarch64 vDSO page exists yet (`crates/core/mm`),
//!     so `crates/core/libsys`'s aarch64 `read_time_csr` twin reads the counter
//!     unconditionally; it is unreachable until the kernel publishes one.

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

// ── Process control (0..=19) ────────────────────────────────────────────
pub const SYS_TEST: u64 = 0;
pub const SYS_PUTCHAR: u64 = 1;
pub const SYS_GETCHAR: u64 = 2;
pub const SYS_EXIT: u64 = 3;
pub const SYS_GETPID: u64 = 10;
pub const SYS_YIELD: u64 = 11;
pub const SYS_FORK: u64 = 12;
pub const SYS_EXEC: u64 = 13;
pub const SYS_WAIT: u64 = 14;
pub const SYS_SLEEP: u64 = 15;
pub const SYS_EXECPATH: u64 = 16;
/// `SYS_SPAWN` — `a0` = pointer to a NUL-terminated path, read as
/// `SYS_EXECPATH` reads its path. Starts a new process from that image and
/// returns its TID, which the caller waits on like any child; no arguments
/// reach the child. The child runs under the seccomp profile bound to the
/// image's SHA-256, and an image with no profile is refused. It starts with
/// the capabilities of the topology entry named after that image, and with
/// none when there is no entry. RFC-0043.
pub const SYS_SPAWN: u64 = 17;

// ── File I/O (20..=29) ──────────────────────────────────────────────────
//
// 20 (`SYS_OPEN`), 22 (`SYS_READ`) and 24 (`SYS_LSEEK`) are RETIRED; see
// [`RETIRED_SYSCALLS`]. What remains is the pair with no typed replacement:
//
// * `SYS_CLOSE` (21) — the untyped close of a DESCRIPTOR. Kept because
//   `captest` issues it raw to watch the kernel refuse to close a typed
//   object with it; retiring the number would retire that proof.
// * `SYS_WRITE` (23) — the console (`STDOUT`/`STDERR`). Owner decision 96:
//   making the console a capability buys no isolation and would break every
//   seccomp profile, so it stays untyped ON PURPOSE. `libsys::write` sends
//   fd 1 and 2 here and every other value to `SYS_FILE_WRITE_TYPED`.
pub const SYS_CLOSE: u64 = 21;
pub const SYS_WRITE: u64 = 23;

// ── IPC (100..=119) ─────────────────────────────────────────────────────
pub const SYS_IPC_FAST_CALL: u64 = 108;
pub const SYS_IPC_FAST_REPLY: u64 = 109;
pub const SYS_IPC_FAST_ACCEPT: u64 = 110;
// 111 was `SYS_IPC_LEASE_GRANT`, which took a raw region id in `a0`. Ring 3
// is never told a region id (`SYS_SHM_CREATE_TYPED` returns a `Cap<Shm>`), so
// a ring-3 lessor could only find one by probing ids until the grant stopped
// refusing. Retired 2026-09-28 (owner decision) for
// [`SYS_IPC_LEASE_GRANT_TYPED`] (603), which takes the capability; the kernel
// grants through `azos_ipc::lease::lease_grant` directly, never through a
// syscall. Number retired, not reused.
/// `SYS_IPC_LEASE_ACCEPT` — `a0 = lessor_tid`. Takes only a lease that lessor
/// granted to the caller; a lease from any other lessor stays pending. With
/// none pending it registers the wait and blocks, polling again after each
/// wake, at most eight times. Returns the lease id, or -1: nothing from that
/// lessor after eight wakes, that lessor exited while the caller waited, no
/// room to register the wait, or `a0 > u32::MAX`.
///
///
/// Bit 32 of `a0` was the accept-and-map flag for one integration round
/// (wave 11, LEASE2); accept-and-map is [`SYS_IPC_LEASE_ACCEPT_MAP`] (613)
/// now, and an `a0` with that bit set answers `-EINVAL`
/// ([`LEASE_ACCEPT_RETIRED_MAP_BIT`]). Any other `a0 > u32::MAX` stays -1.
/// `a1` is not read.
pub const SYS_IPC_LEASE_ACCEPT: u64 = 112;
/// The retired multiplexed accept-and-map flag of [`SYS_IPC_LEASE_ACCEPT`]'s
/// `a0`: refused with `-EINVAL`, so a binary built against that encoding
/// fails loudly instead of accepting without the mapping it expects.
pub const LEASE_ACCEPT_RETIRED_MAP_BIT: u64 = 1 << 32;
pub const SYS_IPC_LEASE_RETURN: u64 = 113;
pub const SYS_IPC_LEASE_FREE: u64 = 114;
// 116 was SYS_CAP_GRANT (cross-task cap delegation, added 2026-08-22).
// Removed 2026-09-03: RFC-0003 is constitutional and says caps are granted
// at boot, not allocated dynamically; this syscall contradicted it and, on
// top of that, shipped without the RFC's own gate (a `CapMaster<T>` the
// issuer must hold — never implemented). The owner decision is boot-only,
// no delegation. Number retired, not reused.

// ── GPIO / PWM / I2C / Motor / Sysinfo / FS / Net (200..=299) ──────────
pub const SYS_GPIO_INFO: u64 = 203;
pub const SYS_PWM_INFO: u64 = 214;
pub const SYS_I2C_SCAN: u64 = 222;
pub const SYS_I2C_INFO: u64 = 223;
pub const SYS_MOTOR_CREATE: u64 = 230;
pub const SYS_MOTOR_INFO: u64 = 234;
pub const SYS_MEMINFO: u64 = 240;
/// `SYS_TASKINFO` (241): a0 = out_ptr, a1 = out_len. Writes
/// [`TASKINFO_BYTES`] about the CALLING task and returns that count.
///
/// Five little-endian `u64`s, in order:
///   0. tid
///   1. priority
///   2. context switches given up voluntarily (yield / block / exit)
///   3. context switches taken by the timer
///   4. the hart the task is running on, at the instant of the call
///
/// **No runtime field, deliberately.** Linux reports one and we do not measure
/// per-task consumed time — `Task` carries only the EDF *budget*, which is a
/// different quantity. Reporting the budget under a name that means
/// consumption is how a plausible number becomes a wrong answer, so the slot
/// is absent rather than filled. The hart is not that kind of field: it is a
/// placement fact with the same meaning as Linux's `getcpu`, and it is what a
/// benchmark needs to tell "the switch got slower" from "more tasks landed on
/// this hart".
///
/// Slots 2 and 3 mirror Linux's `voluntary_ctxt_switches` /
/// `nonvoluntary_ctxt_switches`, and both count SWITCHES rather than calls: a
/// yield that found nothing better to run never switched. That equivalence is
/// the point — a number nobody can compare against anything is not worth a
/// syscall.
pub const SYS_TASKINFO: u64 = 241;

/// Bytes written by [`SYS_TASKINFO`]: five `u64`s.
pub const TASKINFO_BYTES: usize = 5 * 8;
pub const SYS_UPTIME: u64 = 242;
pub const SYS_STAT: u64 = 250;

/// Bytes `SYS_STAT` writes to its buffer (RFC-0048 P2): all little-endian,
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
pub const SYS_READDIR: u64 = 251;

/// Bytes `SYS_READDIR` writes into its name buffer — **always exactly this
/// many**, zero-padding a short name.
///
/// Lives here rather than in `libsys` so the kernel and userspace read ONE
/// definition. It used to exist only on the userspace side, which meant the
/// kernel wrote 64 bytes because a constant it could not see said so.
pub const READDIR_NAME_BYTES: usize = 64;
/// `SYS_MKDIR` — `a0 = path`. From ring 3 it needs a `Cap<File>` with WRITE
/// naming a directory tree the path lies strictly under (wave 10): `-EACCES`
/// without one, `-EINVAL` for a relative path or a `.`/`..` component.
pub const SYS_MKDIR: u64 = 252;
/// `SYS_UNLINK` — `a0 = path`. The same capability rule as [`SYS_MKDIR`].
pub const SYS_UNLINK: u64 = 253;
pub const SYS_CHDIR: u64 = 254;
pub const SYS_GETCWD: u64 = 255;
pub const SYS_MOUNT: u64 = 256;
pub const SYS_UMOUNT: u64 = 257;
pub const SYS_SYNC: u64 = 258;
pub const SYS_NET_INFO: u64 = 260;
pub const SYS_NET_GETIP: u64 = 261;
pub const SYS_NET_SETIP: u64 = 262;
pub const SYS_NET_PING: u64 = 263;
pub const SYS_NET_GETMAC: u64 = 264;
pub const SYS_NET_STATS: u64 = 265;
pub const SYS_DNS_RESOLVE: u64 = 266;
pub const SYS_NTP_SYNC: u64 = 267;
pub const SYS_NTP_OFFSET: u64 = 268;
pub const SYS_MCAST_JOIN: u64 = 269;
pub const SYS_SHUTDOWN: u64 = 270;
pub const SYS_REBOOT: u64 = 271;
pub const SYS_MCAST_LEAVE: u64 = 272;
pub const SYS_MCAST_SEND: u64 = 273;
pub const SYS_SECURE_INIT: u64 = 274;
pub const SYS_SECURE_SEND: u64 = 275;
pub const SYS_SECURE_RECV: u64 = 276;
pub const SYS_DISK_INFO: u64 = 280;
/// `SYS_DISK_READ` — `a0 = sector`, `a1 = sector count`, `a2 = buffer`,
/// `a3 = partition selector`: a `Cap<Disk>` handle, or [`DISK_SEL_ONLY`] for
/// the caller's only disk capability (refused as ambiguous when it holds two
/// or more partitions). Whole-disk: absolute sectors; a partition: sectors
/// relative to its start. A bad handle is `-ECAPSTALE`/`-ECAPKIND`/
/// `-ECAPPERMS`; no capability, or a run outside the partition, `-99`.
pub const SYS_DISK_READ: u64 = 281;
/// `SYS_DISK_WRITE` — as [`SYS_DISK_READ`], and needs WRITE.
pub const SYS_DISK_WRITE: u64 = 282;
/// `SYS_DISK_SIZE` — `a0 = partition selector`, as [`SYS_DISK_READ`]'s
/// `a3`. Sectors of the medium (whole-disk holder, kernel) or of the
/// partition (partition holder). Needs READ.
pub const SYS_DISK_SIZE: u64 = 283;
/// The disk calls' partition selector meaning "the caller's only disk
/// capability": `CAP_NULL`, which no capability handle can be.
pub const DISK_SEL_ONLY: u64 = 0;
pub const SYS_FDT_INFO: u64 = 290;
pub const SYS_FDT_DUMP: u64 = 291;

// ── Driver-server / Robot / Platform / Signals / Pipes (300..=369) ─────
pub const SYS_DRV_REGISTER: u64 = 300;
pub const SYS_DRV_UNREGISTER: u64 = 301;
pub const SYS_DRV_MUNMAP: u64 = 303;
pub const SYS_DRV_IRQ_WAIT: u64 = 304;
pub const SYS_DRV_IRQ_ACK: u64 = 305;
pub const SYS_DRV_DMA_ALLOC: u64 = 306;
pub const SYS_DRV_DMA_FREE: u64 = 307;
pub const SYS_DRV_DMA_SYNC: u64 = 308;
pub const SYS_DRV_HEARTBEAT: u64 = 309;
pub const SYS_DRV_GET_DEVICE: u64 = 310;
/// `SYS_DRV_INVOKE` — userspace bridge into the RFC-0002 Driver
/// registry. Looks up the driver registered for `kind`, then calls
/// `handle_request(op, input, output)` on it via the `dyn Driver`
/// trait object.
///
/// Args:
/// - `a0 = kind` (DRV_KIND_*; matches `azos_driver_server`)
/// - `a1 = op`   (driver-defined op code, e.g. `UART_OP_WRITE`)
/// - `a2 = input_ptr`   (userspace; may be 0 if `input_len == 0`)
/// - `a3 = input_len`   (≤ [`DRIVER_INVOKE_MAX_INPUT_BYTES`])
/// - `a4 = output_ptr`  (userspace; may be 0 if `output_cap == 0`)
/// - `a5 = output_cap`  (≤ [`DRIVER_INVOKE_MAX_OUTPUT_BYTES`])
///
/// Returns the number of bytes written to `output` (≥ 0) on
/// success, or `-Errno`. The driver's [`DriverError`] is mapped
/// to the standard errno table (e.g. `BadOp → ENOSYS`,
/// `NotInitialized → ENODEV`, `BadInput → EINVAL`,
/// `BadOutput → ERANGE`, `Busy → EAGAIN`, `IoFault → EIO`,
/// `Unsupported → ENOSYS`, `NoMem → ENOMEM`).
pub const SYS_DRV_INVOKE: u64 = 311;
/// Upper bound on the input payload for [`SYS_DRV_INVOKE`].
/// Per-call stack buffer in the kernel handler — keep small so we
/// don't blow the syscall stack frame. Large transfers should use
/// the F15 zero-copy pipeline (separate syscall family).
pub const DRIVER_INVOKE_MAX_INPUT_BYTES: usize = 256;
/// Upper bound on the output payload for [`SYS_DRV_INVOKE`].
pub const DRIVER_INVOKE_MAX_OUTPUT_BYTES: usize = 256;
pub const SYS_ROBOT_INIT: u64 = 320;
pub const SYS_ROBOT_START: u64 = 321;
pub const SYS_ROBOT_STOP: u64 = 322;
pub const SYS_ROBOT_PAUSE: u64 = 323;
pub const SYS_ROBOT_RESUME: u64 = 324;
pub const SYS_ROBOT_ESTOP: u64 = 325;
pub const SYS_ROBOT_MOVE: u64 = 326;
pub const SYS_ROBOT_FORWARD: u64 = 327;
pub const SYS_ROBOT_ROTATE: u64 = 328;
pub const SYS_ROBOT_INFO: u64 = 329;
pub const SYS_SENSOR_INFO: u64 = 330;
pub const SYS_SENSOR_ADD: u64 = 331;
pub const SYS_PLATFORM_INFO: u64 = 340;
pub const SYS_PLATFORM_TYPE: u64 = 341;

// ── Sockets (370..=389) ─────────────────────────────────────────────────
pub const SYS_SOCKET: u64 = 370;
pub const SYS_BIND: u64 = 371;
pub const SYS_LISTEN: u64 = 372;
pub const SYS_ACCEPT: u64 = 373;
pub const SYS_CONNECT: u64 = 374;
pub const SYS_SEND: u64 = 375;
pub const SYS_RECV: u64 = 376;
pub const SYS_SENDTO: u64 = 377;
pub const SYS_RECVFROM: u64 = 378;
pub const SYS_SOCK_SHUTDOWN: u64 = 379;
pub const SYS_GETSOCKNAME: u64 = 380;
pub const SYS_GETPEERNAME: u64 = 381;

// ── Service manager (390..=399) ─────────────────────────────────────────
pub const SYS_SERVICE_REGISTER: u64 = 390;
pub const SYS_SERVICE_UNREGISTER: u64 = 391;
pub const SYS_SERVICE_DISCOVER: u64 = 392;
pub const SYS_SERVICE_HEARTBEAT: u64 = 393;
pub const SYS_SERVICE_LIST: u64 = 394;
pub const SYS_SERVICE_INFO: u64 = 395;
pub const SYS_SERVICE_START: u64 = 396;
pub const SYS_SERVICE_STOP: u64 = 397;

// ── Memory + misc (400..=429) ───────────────────────────────────────────
pub const SYS_BRK: u64 = 400;
pub const SYS_MMAP: u64 = 401;
pub const SYS_MUNMAP: u64 = 402;
pub const SYS_FORK_COW: u64 = 403;
pub const SYS_ALLOC_DEMAND: u64 = 404;
pub const SYS_ADC_READ: u64 = 410;
/// `SYS_BUZZER_TONE` — `a0` = frequency in Hz (clamped to 20 000), `a1` =
/// duration in ms (clamped to 10 000). Returns once the tone has STARTED, not
/// when it ends: the ring-3 buzzer driver plays it against its own clock
/// (wave 9; the in-kernel driver busy-waited for the whole duration). A later
/// buzzer call replaces a tone still playing.
pub const SYS_BUZZER_TONE: u64 = 420;
pub const SYS_BUZZER_OFF: u64 = 421;

// ── Security (430..=499) ────────────────────────────────────────────────
pub const SYS_SECCOMP: u64 = 430;

// ── IO ring / channels / MMIO / IRQ / ports / handles / trace (500..=529)
/// a0 = MMIO region index, a1 = access (CapPerms READ or READ|WRITE); RFC-0043.
pub const SYS_MMIO_MAP: u64 = 509;
pub const SYS_IRQ_BIND: u64 = 510;
pub const SYS_TRACE_DUMP: u64 = 518;

// ── Driver framework (520..=527) ────────────────────────────────────────
pub const SYS_DRIVER_POLL_EVENT: u64 = 522;
pub const SYS_DRIVER_FETCH_REQ: u64 = 523;
pub const SYS_DRIVER_REPLY: u64 = 524;
// 525 (SYS_DRIVER_REQUEST) and 526 (SYS_DRIVER_TRY_REPLY): retired in wave 11,
// see `RETIRED_SYSCALLS`.
pub const SYS_DRIVER_STATS: u64 = 527;

// ── Cap-typed IPC (528..=549) — RFC-0003 W3+ ────────────────────────────
/// `SYS_CHAN_WRITE_TYPED` — `Cap<Channel>` typed channel write.
///
/// `a0 = cap_handle (u32)`, `a1 = data_ptr`, `a2 = len`.
///
/// Returns `0` on success or `-Errno`. Distinguishes
/// `ECAPSTALE` / `ECAPKIND` / `ECAPPERMS` from `EBADF` / `EAGAIN`.
pub const SYS_CHAN_WRITE_TYPED: u64 = 528;
/// `SYS_CHAN_READ_TYPED` — `Cap<Channel>` typed channel read.
pub const SYS_CHAN_READ_TYPED: u64 = 529;

/// `SYS_PORT_CREATE_TYPED` — allocates a port + grants a `Cap<Port>`
/// into the calling task's cap-table.
///
/// No args. Returns the raw `CapHandle` as `i64` (positive) on
/// success, or `-Errno` on failure.
pub const SYS_PORT_CREATE_TYPED: u64 = 530;
/// `SYS_PORT_POLL_TYPED` — `Cap<Port>` typed event dequeue.
///
/// `a0 = cap_handle (u32)`, `a1 = out_ptr (PortEvent buffer, 16 B)`.
/// Returns the number of bytes copied (16) on success, or `-Errno`.
pub const SYS_PORT_POLL_TYPED: u64 = 531;
/// `SYS_PORT_DESTROY_TYPED` — `Cap<Port>` typed port destruction.
///
/// `a0 = cap_handle`. Requires `WRITE`; not refused while degraded
/// mode is contained. Frees the port slot **and revokes the cap**
/// (`port_destroy_cap`, W3-F5), so a later use answers `ECAPSTALE`
/// instead of reaching a port created at the same index.
pub const SYS_PORT_DESTROY_TYPED: u64 = 532;

/// `SYS_SHM_CREATE_TYPED` — allocates a shared-memory region with
/// `a0 = page_count` pages and access mode `a1` (0=ReadOnly,
/// 1=ReadWrite). Mints a `Cap<Shm>` into the caller's cap-table.
///
/// Returns the raw `CapHandle` as `i64` (positive) on success, or
/// `-Errno` (`ENOMEM`, `EINVAL`, `EMFILE`) on failure. On cap-table
/// exhaustion the region is rolled back so callers never observe a
/// half-created region.
pub const SYS_SHM_CREATE_TYPED: u64 = 533;
/// `SYS_SHM_ACQUIRE_TYPED` — bumps the refcount of the region
/// referenced by `a0 = cap_handle`. `a1 = out_ptr` receives an 8-byte
/// blob: `page_count u32 LE`, `perms u8` (0=RO,1=RW), 3 bytes pad.
///
/// Requires `READ` on the cap. The reference is given back by
/// [`SYS_SHM_RELEASE_TYPED`], with the caller's others.
pub const SYS_SHM_ACQUIRE_TYPED: u64 = 534;
/// `SYS_SHM_RELEASE_TYPED` — removes the caller's mapping of the region,
/// then gives back every reference the caller holds on it (the creation
/// reference, [`SYS_SHM_ACQUIRE_TYPED`]'s and [`SYS_SHM_MAP_TYPED`]'s);
/// frees all backing pages when no task holds one.
///
/// `a0 = cap_handle`. Requires `READ`. The cap **is revoked** by the same
/// call (`shm_release_cap`, W3-F5), so the references go with it; one that a
/// failed [`SYS_SHM_MAP_TYPED`] kept stays until the caller exits. `-EBADF`
/// when the caller holds no reference.
pub const SYS_SHM_RELEASE_TYPED: u64 = 535;

/// `SYS_IORING_CREATE_TYPED` — allocates an io_ring and mints a
/// `Cap<IoRing>` into the caller's cap-table.
///
/// `a0 = out_ptr` (8 bytes, `u64 LE`): ring 3 receives the user address
/// of the ring page, mapped user RW and never executable in the task's
/// shm/MMIO window and unmapped by [`SYS_IORING_DESTROY_TYPED`]; a kernel
/// caller receives the physical address.
///
/// Returns the raw `CapHandle` as `i64` (positive) on success, or
/// `-Errno` (`ENOMEM`, also when the page cannot be mapped; `EMFILE`,
/// `EFAULT`). On cap-table exhaustion the ring is rolled back so callers
/// never observe a half-created ring.
pub const SYS_IORING_CREATE_TYPED: u64 = 536;
/// `SYS_IORING_SUBMIT_TYPED` — process SQEs on the ring referenced
/// by `a0 = cap_handle`. Returns the number of SQEs processed
/// (`u32`, sign-extended into `i64` ≥ 0) or `-Errno`. Requires
/// `WRITE` on the cap.
///
/// Each entry is checked against the submitter's seccomp profile (the
/// entry's typed syscall number), the owner's capability and, for a write,
/// containment, and runs through the same function its typed call runs. A
/// refused entry completes with `IORING_CQE_F_REFUSED` set and `-Errno` in
/// `result`. `-EBUSY` when an entry is pending and the completion queue is
/// full: nothing ran, and `sq_head` still names that entry.
pub const SYS_IORING_SUBMIT_TYPED: u64 = 537;
/// `CqEntry.flags` bit: the kernel refused the entry, and `result` holds
/// `-Errno` (RFC-0041 §E). Mirrors `azos_ipc::io_ring::CQE_F_REFUSED`.
pub const IORING_CQE_F_REFUSED: u32 = 1;
/// `SYS_IORING_DESTROY_TYPED` — frees the io_ring + its backing
/// page. `a0 = cap_handle`. Requires `WRITE`; not refused while
/// degraded mode is contained. The cap **is revoked** by the same
/// call (`io_ring_destroy_cap`, W3-F5).
pub const SYS_IORING_DESTROY_TYPED: u64 = 538;

/// `SYS_GPIO_READ_TYPED` — read a GPIO pin via `Cap<Gpio>`.
/// `a0 = cap_handle`. Returns 0 or 1 on success, or `-Errno`.
/// Requires `READ` permission on the cap. The cap's resource_id
/// is the pin number; topology grant determines which pin a task
/// may touch.
pub const SYS_GPIO_READ_TYPED: u64 = 539;
/// `SYS_GPIO_WRITE_TYPED` — drive a GPIO pin. `a0 = cap_handle`,
/// `a1 = val` (low bit only). Returns 0 or `-Errno`. Requires `WRITE`.
pub const SYS_GPIO_WRITE_TYPED: u64 = 540;
/// `SYS_GPIO_SET_DIR_TYPED` — set pin direction. `a0 = cap_handle`,
/// `a1 = 0` (input) or `1` (output). Returns 0 or `-Errno`.
/// Requires `WRITE`.
pub const SYS_GPIO_SET_DIR_TYPED: u64 = 541;

/// `SYS_I2C_READ_TYPED` — read from a Cap<I2c> slave.
/// `a0 = cap`, `a1 = reg`, `a2 = buf_ptr (user)`, `a3 = buf_len`.
/// Returns bytes read (≥ 0) or `-Errno`. Requires `READ`.
pub const SYS_I2C_READ_TYPED: u64 = 542;
/// `SYS_I2C_WRITE_TYPED` — write to a Cap<I2c> slave.
/// `a0 = cap`, `a1 = data_ptr (user)`, `a2 = data_len`.
/// `data[0]` is by I2C convention the register address.
/// Returns 0 or `-Errno`. Requires `WRITE`.
pub const SYS_I2C_WRITE_TYPED: u64 = 543;
/// `SYS_I2C_DETECT_TYPED` — probe whether the slave ACKs.
/// `a0 = cap`. Returns 1 (present) / 0 (absent), or `-Errno`.
/// Requires `READ`.
pub const SYS_I2C_DETECT_TYPED: u64 = 544;

/// Per-call buffer cap for [`SYS_I2C_READ_TYPED`] and
/// [`SYS_I2C_WRITE_TYPED`]. Mirrors the DRIVER_INVOKE caps —
/// larger transfers should use the F15 zero-copy pipeline.
pub const I2C_TYPED_MAX_BYTES: usize = 256;

/// `SYS_PWM_ENABLE_TYPED` — start the PWM channel referenced by
/// `Cap<Pwm>`. `a0 = cap`. Returns 0 or `-Errno`. Requires `WRITE`.
pub const SYS_PWM_ENABLE_TYPED: u64 = 545;
/// `SYS_PWM_DISABLE_TYPED` — stop. `a0 = cap`. Requires `WRITE`.
pub const SYS_PWM_DISABLE_TYPED: u64 = 546;
/// `SYS_PWM_SET_PERIOD_TYPED` — `a0 = cap`, `a1 = period_ns`
/// (u32 nanoseconds). Requires `WRITE`.
pub const SYS_PWM_SET_PERIOD_TYPED: u64 = 547;
/// `SYS_PWM_SET_DUTY_TYPED` — `a0 = cap`, `a1 = duty_ns` (u32).
/// Requires `WRITE`.
pub const SYS_PWM_SET_DUTY_TYPED: u64 = 548;
/// `SYS_PWM_SET_DUTY_PCT_TYPED` — `a0 = cap`, `a1 = pct`
/// (0..=100). Requires `WRITE`.
pub const SYS_PWM_SET_DUTY_PCT_TYPED: u64 = 549;

// ── Cap-typed Phase-1 extension (550..=579) — RFC-0003 W5 batch 5.4+
// The original cap-typed range 528..=549 filled at PWM (5.3). The
// hardware-cap families that don't fit (Motor, Sensor, future
// ESC/Lidar) take this second slot, and so do Cap<File> (563-566),
// Cap<Socket> (567-570) and its multicast pair (571-572). Widened from 569
// to 579 by owner decision
// 2026-09-13, when the socket family needed a fourth number. The ranges, and
// the rule the minting calls in them follow, are recorded in RFC-0003's
// 2026-09-13 addendum. 573-578 are reserved for RFC-0040 gap 1 (after 572).
/// `SYS_MOTOR_SET_TARGET_TYPED` — `a0 = cap`, `a1 = speed_l u16`
/// (low half = signed i16), `a2 = speed_r u16`. Requires `WRITE` — and,
/// since 2026-08-24 (`Cap<Motor>` per-motor granularity, RFC-0003 P1), the
/// caller's cap table must hold `WRITE` on **both** `Motor(0)` and
/// `Motor(1)`, not just the wheel named by `cap`: this syscall actuates the
/// shared drivetrain PID loop for both wheels at once. See
/// `crates/core/ipc/src/motor_cap.rs::require_pair_write`.
pub const SYS_MOTOR_SET_TARGET_TYPED: u64 = 550;
/// `SYS_MOTOR_TICK_TYPED` — `a0 = cap`, `a1 = ticks_l u64` (cast
/// from i64), `a2 = ticks_r u64`, `a3 = now u64`,
/// `a4 = out_ptr` (8 bytes: pwm_l i32 LE, pwm_r i32 LE).
/// Returns 8 (bytes written) or `-Errno`. Requires `WRITE` on both
/// `Motor(0)` and `Motor(1)` — same pair rule as 550; see
/// `crates/core/ipc/src/motor_cap.rs::require_pair_write`.
pub const SYS_MOTOR_TICK_TYPED: u64 = 551;
/// `SYS_MOTOR_ENABLE_TYPED` — `a0 = cap`, `a1 = 0|1`. Requires `WRITE` on
/// both `Motor(0)` and `Motor(1)` — same pair rule as 550; see
/// `crates/core/ipc/src/motor_cap.rs::require_pair_write`.
pub const SYS_MOTOR_ENABLE_TYPED: u64 = 552;
/// `SYS_MOTOR_ENABLED_TYPED` — `a0 = cap`. Returns 0|1 or `-Errno`.
/// Requires `READ`. NOT pair-wide: unlike its WRITE siblings, this is a
/// read of shared state and only needs the single cap named by `a0` — see
/// `crates/core/ipc/src/motor_cap.rs`'s module doc for why this one syscall is
/// the exception.
pub const SYS_MOTOR_ENABLED_TYPED: u64 = 553;
/// `SYS_MOTOR_SET_GAINS_TYPED` — `a0 = cap`, `a1 = kp` (i32 in
/// low u32), `a2 = ki`, `a3 = kd`. Requires `WRITE` on both `Motor(0)` and
/// `Motor(1)` — same pair rule as 550; see
/// `crates/core/ipc/src/motor_cap.rs::require_pair_write`.
pub const SYS_MOTOR_SET_GAINS_TYPED: u64 = 554;
/// `SYS_MOTOR_RESET_TYPED` — `a0 = cap`. Requires `WRITE` on both
/// `Motor(0)` and `Motor(1)` — same pair rule as 550; see
/// `crates/core/ipc/src/motor_cap.rs::require_pair_write`.
pub const SYS_MOTOR_RESET_TYPED: u64 = 555;

/// `SYS_DRIVER_REGISTER_TYPED` — `a0 = cap` (`Cap<DriverRegistry>`),
/// `a1 = mmio_base`, `a2 = mmio_size`, `a3 = irq`. Requires `WRITE`.
///
/// **There is no `kind` argument, and that is the point of the syscall.**
/// The untyped `SYS_DRIVER_REGISTER` (520, retired) took the kind in `a0` and
/// gated on `DriverRegistry(a0)`; here the kind is read out of the
/// capability, so registering as a kind the caller does not hold is not an
/// expressible request rather than a refused one.
pub const SYS_DRIVER_REGISTER_TYPED: u64 = 556;
/// `SYS_DRIVER_UNREGISTER_TYPED` — `a0 = cap`. Requires `WRITE`, same as
/// register: unregistering a driver denies the device, which for a motor
/// driver is a stopped robot. Unlike register it is a release, so it is not
/// refused while RFC-0036 containment is armed (owner decision 2026-09-13).
pub const SYS_DRIVER_UNREGISTER_TYPED: u64 = 557;

/// `SYS_CAP_LOOKUP` — `a0 = CapKind as u8`, `a1 = resource index`.
/// Returns the caller's own `CapHandle` as a positive `u32`, or `-Errno`
/// (`ENOENT` if the caller holds no such capability, `EINVAL` for an
/// unrecognised kind).
///
/// **The read half that was missing.** Twenty-one of the thirty typed
/// syscalls above require a handle the caller must already have, and until
/// this call there was no way for ring 3 to obtain one for a capability
/// minted at boot — so every hardware family's typed path had no possible
/// caller. Only `PORT_CREATE`/`SHM_CREATE`/`IORING_CREATE` (which return the
/// handle they mint) and the calls reachable from them were usable.
///
/// **Not a resurrection of `SYS_CAP_GRANT` (116, removed 2026-09-03).** That
/// created authority in another task's table. This creates none anywhere: it
/// reads the CALLER's own table and answers "which handle names the thing I
/// already hold?". A lookup that returned a handle for a capability the
/// caller does not hold would BE a mint, which is the property its tests are
/// written around.
pub const SYS_CAP_LOOKUP: u64 = 558;

/// `SYS_WAIT_STATUS` — `a0 = *mut i32` (may be null). Reaps one finished
/// child, writes its exit code through `a0`, and returns the child's TID;
/// returns `-1` without writing when no child has finished.
///
/// `WNOHANG`, like [`SYS_WAIT`] (14), whose only shortcoming this addresses:
/// the kernel records a child's exit code (`azos_sched::note_exit`) and
/// `SYS_WAIT` discards it, so a parent could learn WHICH child finished and
/// never HOW. On a tree built with `panic = "abort"`, the difference between
/// a clean exit and an abort is the difference between a task that finished
/// and a task that panicked.
///
/// A new number rather than an argument on 14: `SYS_WAIT` takes none, and
/// `libsys`'s `syscall0` does not set `a0`, so adding an out-pointer there
/// would have the kernel write through whatever that register happened to
/// hold for every existing caller.
pub const SYS_WAIT_STATUS: u64 = 559;

/// `SYS_MOTOR_SPEED_TYPED` — `a0 = cap` (`Cap<Motor>`), `a1 = speed_pct`
/// (0 stops). Returns 0, or `-Errno`. Requires `WRITE`.
///
/// The typed twin of the retired `SYS_MOTOR_SPEED` (232), and the only typed call that
/// ACTUATES a wheel: 550-555 write shared PID state for `rt_motor_task` to
/// consume, which is a different operation. Without this there was no typed
/// way to express "stop this wheel now", so every ring-3 program that
/// actuates directly — `reflex`, the obstacle-avoidance reflex — was stuck on
/// the untyped path.
///
/// **One wheel, no pair rule.** The wheel comes from the capability, not from
/// an argument; and unlike 550-555 it does NOT require WRITE on both, because
/// 232 does not either. Making the typed form stricter than the call it
/// mirrors would change the authority under cover of migrating it.
pub const SYS_MOTOR_SPEED_TYPED: u64 = 560;

/// `SYS_SENSOR_READ_TYPED` — `a0 = cap` (`Cap<Sensor>`), `a1 = out_ptr`,
/// `a2 = out_len`. Returns bytes written, or `-Errno`. Requires `READ`.
///
/// The typed twin of the retired `SYS_SENSOR_READ` (332). The sensor TYPE comes from
/// the capability, so there is no type argument: reading a sensor the caller
/// does not hold is not expressible, where 332 takes the type in `a0` and
/// relies on `cap_check` to disagree.
///
/// This closes the largest remaining untyped family. `sys_sensor_read` has
/// fifteen ring-3 call sites — more than every other hardware family
/// combined — and none could migrate, because until now the `Sensor` kind
/// had no typed syscall, no minter and no way for a grant to reach ring 3.
pub const SYS_SENSOR_READ_TYPED: u64 = 561;

/// `SYS_WAITPID` — `a0 = child_tid`, `a1 = *mut i32` (may be null). Reaps THAT
/// child, writes its exit code through `a1`, returns its TID. `-1` if that
/// child is alive, `-ECHILD` if it is not a child of the caller (or was
/// already reaped), `-EFAULT` if the status pointer is unwritable.
///
/// `WNOHANG`, like [`SYS_WAIT`] (14) and [`SYS_WAIT_STATUS`] (559).
///
/// **What 14 and 559 cannot do.** Both return the FIRST finished child, so a
/// parent with several children learns that *a* child died and never which,
/// and a caller waiting for one must consume and discard its siblings'
/// notices. `userspace/bench/vsbench`'s life-cycle lane had to do that, and its
/// first version mistook a sibling's notice for a failure and failed on a real
/// boot — which is how this gap was found.
///
/// **`-1` and `-ECHILD` are different answers on purpose.** "Not finished yet"
/// is a reason to poll again; "not your child" never becomes true however long
/// you wait. Collapsing them would put the caller back to spinning against a
/// bound.
pub const SYS_WAITPID: u64 = 562;

// ── Cap<File> (563-566) ─────────────────────────────────────────────────────
// Files as capabilities. These were added ALONGSIDE the descriptor calls and
// have now REPLACED them: `SYS_OPEN` (20) and `SYS_READ` (22) are retired, and
// `libsys::open`/`read` are the POSIX-named front of 563/564. The handle's
// `resource` is the descriptor, and the cap table never learns more about a
// file than that (the TCB rule: the fd→inode mapping stays behind `FileOps`).
//
// The descriptor has not gone away — it is no longer NAMEABLE from ring 3. A
// caller holds a handle whose kind bits the kernel checks, so the integer it
// passes can no longer be read as some other object's index; that is the whole
// point, and it is what the retirement of 20 and 22 finishes.

/// `SYS_FILE_OPEN_TYPED` — `a0 = path_ptr` (NUL-terminated), `a1 = flags`.
///
/// Opens a path and MINTS a `Cap<File>` into the caller's own table —
/// "mint what you create": `READ` for `O_RDONLY`, `WRITE` for `O_WRONLY`, both
/// for `O_RDWR`. An access mode of 3 is refused with `-EINVAL` before anything
/// is opened. Returns the raw handle (`>= 0`), `-1` when the open itself fails,
/// or `-EMFILE` when the cap table is full — in which case the descriptor it
/// just opened is closed again rather than left behind with no name.
pub const SYS_FILE_OPEN_TYPED: u64 = 563;

/// `SYS_FILE_READ_TYPED` — `a0 = cap`, `a1 = buf`, `a2 = count`. Requires
/// `READ`. Clamped to `IO_MAX_BYTES` and copied out with the same checked
/// path the retired descriptor read used. Returns bytes read or `-Errno`.
pub const SYS_FILE_READ_TYPED: u64 = 564;

/// `SYS_FILE_WRITE_TYPED` — `a0 = cap`, `a1 = buf`, `a2 = count`. Requires
/// `WRITE`, so degraded mode (RFC-0036) refuses it with `-EAGAIN` the way it
/// refuses every write through a capability. Returns bytes written or `-Errno`.
pub const SYS_FILE_WRITE_TYPED: u64 = 565;

/// `SYS_CLOSE_TYPED` — `a0 = cap`. Revokes the capability and releases what it
/// names, choosing by the handle's kind — one close for every kind that has
/// one, which is what a single handle namespace is for. A kind with no close
/// here is refused with `-ECAPKIND`. Returns 0 or `-Errno`.
pub const SYS_CLOSE_TYPED: u64 = 566;

// ── Cap<Socket> (567-570) ───────────────────────────────────────────────────
// Sockets as capabilities, one-to-one with the untyped calls they sit beside
// (owner decision 2026-09-13, which also extended the typed range to 579).
// `bind`, `sendto` and `recvfrom` stay untyped. Close goes through
// `SYS_CLOSE_TYPED` (566) like every other kind.

/// `SYS_SOCKET_TYPED` — `a0 = domain`, `a1 = type`, `a2 = proto`.
///
/// Creates a socket like `SYS_SOCKET`, owned by the caller, and MINTS a
/// `Cap<Socket>` with `READ | WRITE` into the caller's own table. Returns the
/// raw handle (`>= 0`), `-1` if the socket could not be created (the per-task
/// quota included), or `-EMFILE` when the cap table is full — in which case the
/// socket is closed again.
pub const SYS_SOCKET_TYPED: u64 = 567;

/// `SYS_CONNECT_TYPED` — `a0 = cap`, `a1 = sockaddr_ptr`, `a2 = addrlen`.
/// Requires `WRITE`. Returns what `SYS_CONNECT` returns, or `-Errno` for the
/// capability.
pub const SYS_CONNECT_TYPED: u64 = 568;

/// `SYS_SEND_TYPED` — `a0 = cap`, `a1 = buf`, `a2 = len`. Requires `WRITE`, so
/// degraded-mode containment refuses it with `-EAGAIN` like every write
/// through a capability (owner decision 2026-09-13). Returns bytes sent.
pub const SYS_SEND_TYPED: u64 = 569;

/// `SYS_RECV_TYPED` — `a0 = cap`, `a1 = buf`, `a2 = len`. Requires `READ`,
/// which containment leaves live. Returns bytes received.
pub const SYS_RECV_TYPED: u64 = 570;

// ── Cap<Socket> multicast (571-572) ─────────────────────────────────────────
// IPv4 group membership as two calls on a `Cap<Socket>` rather than a
// `setsockopt` (owner decision 2026-09-13). A membership belongs to its
// socket: every path that releases the socket — `SYS_CLOSE_TYPED`,
// `SYS_SOCK_SHUTDOWN`, task exit — gives its groups back.

/// `SYS_MCAST_JOIN_TYPED` — `a0 = cap` (`Cap<Socket>`), `a1 = group` as a `u32`
/// in network byte order (`239.1.2.3` is `0xEF01_0203`). Requires `WRITE`, so
/// degraded-mode containment refuses it with `-EAGAIN`.
///
/// Returns 0, or `-EINVAL` for a group outside `224.0.0.0/4` or inside
/// `224.0.0.0/24` (link-local control; `224.0.0.1` is joined implicitly), an
/// `a1` wider than 32 bits, or a socket that is not UDP; `-EQUOTA` when the
/// socket already holds four groups, or when the task behind the capability
/// already holds `MAX_MCAST_GROUPS_PER_TASK` groups across all of its
/// sockets; `-ENOSPC` when the machine-wide group table is full; `-EBADF` if
/// the socket behind the capability is gone. A repeat join of a group the
/// socket holds returns 0 and changes nothing.
/// Delivery is by port, as for any datagram: group traffic reaches the socket
/// bound to the destination port.
pub const SYS_MCAST_JOIN_TYPED: u64 = 571;

/// `SYS_MCAST_LEAVE_TYPED` — `a0 = cap`, `a1 = group` (same encoding). Needs no
/// permission beyond a live `Cap<Socket>`, like the close, so containment
/// leaves it live: giving a membership back is cleanup. Returns 0, or
/// `-EINVAL` for a group this socket does not hold (an invalid group
/// included) or a socket that is not UDP.
pub const SYS_MCAST_LEAVE_TYPED: u64 = 572;

// ── RFC-0040 gap 1: typed forms (573-578) ────────────────────────────────────
// The typed replacements for the untyped channel, shared-memory, port and motor
// calls gap 1 retires. Every one dispatches and is a member of
// `CAP_TYPED_SYSCALLS`.

/// `SYS_CHAN_CREATE_TYPED` — no arguments.
///
/// Creates a channel owned by the caller and MINTS a `Cap<Channel>` with
/// `READ | WRITE` into the caller's own table. Returns the raw handle, or
/// `-EQUOTA` when a ring-3 caller already owns `MAX_CHANNELS / 2` live channels
/// (however created; kernel callers are exempt), or `-EMFILE` when the pool is
/// exhausted, a generation wrap sweep is running or the caller's table is full.
/// Each channel a ring-3 caller creates holds a slot in its table, so where
/// `MAX_CHANNELS / 2` exceeds `MAX_CAPS_PER_TASK` the table fills first and
/// `-EQUOTA` is not reached.
/// The channel index is not published: the untyped channel calls it would
/// serve are retired in gap 1 (owner decision 2026-09-14), so nothing addresses
/// a channel by index. [`SYS_CLOSE_TYPED`] destroys the channel.
pub const SYS_CHAN_CREATE_TYPED: u64 = 573;

/// `SYS_SHM_MAP_TYPED` — `a0 = cap` (`Cap<Shm>`).
///
/// The typed form of `SYS_IPC_MAP` (115). Maps the region into the caller's
/// address space with the region's own access mode and returns the base
/// address, or `-Errno`. Requires `READ`; a writable region also requires
/// `WRITE`, which containment refuses (`-EAGAIN`). The mapping is recorded as
/// `SYS_IPC_MAP` recorded it, one per task and region, and
/// [`SYS_SHM_RELEASE_TYPED`] removes it before it gives back the caller's references. In
/// order: `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS` / `-EAGAIN` for the
/// capability; `-EINVAL` for a kernel caller; `-EBUSY` when the caller already
/// maps the region; `-EBADF` when the region has no room for another holder;
/// `-ENOMEM` when the pages could not be mapped (the reference is kept then, until the caller exits).
pub const SYS_SHM_MAP_TYPED: u64 = 574;

/// `SYS_PORT_BIND_TYPED` — `a0 = cap` (`Cap<Port>`), `a1 = source type`
/// (`SYS_PORT_BIND`'s encoding: 0 channel, 1 ring, 2 IRQ, 3 timer) `|`
/// [`PORT_BIND_F_REMOVE`], `a2 = source`, `a3 = key`.
///
/// The typed form of `SYS_PORT_BIND` (512), whose source is a raw index. Binds
/// a source to the port and returns 0, or `-Errno`. The port capability needs
/// `WRITE`, which containment refuses (`-EAGAIN`). The source, per type, and
/// the capability the caller must hold for it:
///
/// - 0, a channel: `a2` a `Cap<Channel>` with `READ`. Every message sent on
///   it marks the source pending (an event with type 1, `source_id` = `a2`).
/// - 1, an io_ring: `a2` a `Cap<IoRing>` with `READ`. Every submit or SQ
///   poller pass that writes a completion marks it pending (type 2).
/// - 2, an IRQ: `a2` a `Cap<Irq>` with `READ`. Every delivery queues one
///   event (type 3, `source_id` = the line).
/// - 3, a timer: `a2` an absolute deadline in nanoseconds on the time counter
///   (`SYS_SLEEP_UNTIL`'s unit); no capability (the timer is the port's own).
///   Fires once (type 4) at the first poll or wait at or after the deadline;
///   a bind with a key already armed re-arms it.
///
/// Channel and io_ring sources are edge-triggered and coalesced: one event
/// stands for every message (completion) since the last one; drain after it.
/// A message already queued at bind time is reported once. One channel or
/// ring reports to one port; it occupies one slot of it (a second bind of the
/// same object updates the key). A channel or io_ring binding is tied to the
/// capability it was made with (wave 11, LEASE3): it ends when that
/// capability is revoked (its holder's exit included), follows it when it is
/// moved to another task, and otherwise ends when the source or the port is
/// destroyed or the source is removed. A timer or IRQ binding is not tied to
/// a capability. The kernel keeps each binding as the port's (index,
/// generation) and compares it at delivery (owner decision 2026-09-14), so a
/// destroyed and reissued port does not receive the old binding's events.
///
/// With [`PORT_BIND_F_REMOVE`] in `a1`, removes every channel (0), io_ring (1)
/// or timer (3) source of that type bound with key `a3` (`a2` is ignored)
/// and returns 0, or `-ENOENT` when none was; an IRQ binding (2) is not
/// removable this way (`-EINVAL`).
///
/// In order: the port capability's `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS` /
/// `-EAGAIN`; `-EINVAL` for a source type above 3 or an unknown flag; the
/// source capability's `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS`;
/// `-ECAPSTALE` for a port (or source) destroyed before the binding was
/// stored, or a source capability revoked or moved while it was being stored;
/// `-EMFILE` when the port's source table (Kconfig
/// `MAX_PORT_SOURCES`) or the IRQ binding table is full; `-EBUSY` when the
/// channel or ring already reports to another live port; `-ENODEV` when the
/// interrupt controller cannot deliver the line (a source it does not
/// implement or was not delegated), with nothing left bound.
/// `SYS_IRQ_BIND` (510) answers `-ENODEV` for the same case.
pub const SYS_PORT_BIND_TYPED: u64 = 575;

/// [`SYS_PORT_BIND_TYPED`] flag in `a1`: remove the sources of the type in
/// the low byte bound with the key in `a3`, instead of binding one.
pub const PORT_BIND_F_REMOVE: u64 = 0x100;

/// `SYS_MOTOR_DIRECTION_TYPED` — `a0 = cap` (`Cap<Motor>`), `a1 = direction`
/// (0 forward, 1 backward, 2 brake, 3 coast; 4 or more is `-EINVAL`, owner
/// decision 2026-09-14 — where the retired 231 coasted).
///
/// The typed form of `SYS_MOTOR_ENABLE` (231), which sets one wheel's
/// direction at 50 % duty. Requires `WRITE`. The wheel comes from the
/// capability, with no pair rule and no containment step, like
/// [`SYS_MOTOR_SPEED_TYPED`] (560): the motor layer's halt rule decides, so
/// while an e-stop is latched or containment is armed a brake or coast is
/// carried out and a forward or backward answers `-EAGAIN`. A direction of 4
/// or more answers `-EINVAL` before any pin is written. Returns 0, that
/// `-EAGAIN`, the motor layer's negative code, `-EINVAL`, or `-ECAPSTALE` /
/// `-ECAPKIND` / `-ECAPPERMS` for the capability.
pub const SYS_MOTOR_DIRECTION_TYPED: u64 = 576;

/// `SYS_PORT_WAIT_TYPED` — `a0 = cap` (`Cap<Port>`), `a1 = out_ptr`.
///
/// The blocking form of [`SYS_PORT_POLL_TYPED`] (531): it sleeps until an event
/// arrives, writes it through `a1` in 531's 16-byte layout and returns 16, or
/// `-Errno`. A new number rather than a flag on 531, by the [`SYS_WAIT_STATUS`]
/// precedent. Requires `READ`, which containment leaves live. The sleeper's
/// wait names the port as (index, generation) (owner decision 2026-09-14), so a
/// destroy and reissue while it sleeps cannot hand it another port's events. In
/// order: `-EINVAL` for a null `a1`; the capability's `-ECAPSTALE` /
/// `-ECAPKIND` / `-ECAPPERMS`; `-EFAULT` when the 16 bytes at `a1` are not
/// writable user memory, checked before anything is dequeued; `-ECAPSTALE` at
/// once when the port is destroyed before or during the wait; `-EMFILE` when
/// eight tasks already wait on the port; `-EAGAIN` when eight wakes brought
/// nothing. It reports every source [`SYS_PORT_BIND_TYPED`] binds, and while
/// a timer source is armed it sleeps no later than the earliest one (wave 11).
pub const SYS_PORT_WAIT_TYPED: u64 = 577;

/// `SYS_MOTOR_ANGLE_TYPED` — `a0 = cap` (`Cap<Motor>`), `a1 = out_ptr`.
///
/// The typed form of the retired `SYS_MOTOR_ANGLE` (233). Requires `READ`, which
/// containment leaves live. The wheel comes from the capability, its
/// accumulated encoder ticks are written through `a1` (8 bytes, `i64`
/// little-endian), and the return is 0 or `-Errno` only: a refusal cannot be
/// read as a tick count, as 233's `-1` and `-99` can. In order: `-ECAPSTALE` /
/// `-ECAPKIND` / `-ECAPPERMS` for the capability, `-EINVAL` for a wheel with no
/// encoder (only 0 and 1 have one), `-EFAULT` for an out pointer that is not 8
/// writable user bytes.
pub const SYS_MOTOR_ANGLE_TYPED: u64 = 578;

/// Width in bytes of the SYS_MOTOR_TICK_TYPED output blob
/// (pwm_l i32 LE + pwm_r i32 LE).
pub const MOTOR_TICK_OUT_BYTES: usize = 8;

// ── RFC-0041 combined calls (580..=589) ─────────────────────────────────

/// `SYS_IPC_FAST_REPLY_ACCEPT` — a server's reply and its next accept in one
/// trap (RFC-0041 §C). `a0` = the handle from the previous accept, `a2..a5` =
/// the four reply words. `a1` is not read: libsys preloads the accept's
/// not-written sentinel there.
///
/// Fail-fast (owner decision 2026-09-15). A reply that is not delivered
/// accepts nothing and returns at once: `-2` for a stale handle, `-3` for any
/// other refusal. A delivered reply continues exactly as `SYS_IPC_FAST_ACCEPT`:
/// `a0` = the next handle with `a1` = caller TID and `a2..a5` = its words, or
/// `-1` when nothing arrived within the accept's eight wakes.
pub const SYS_IPC_FAST_REPLY_ACCEPT: u64 = 580;

/// `SYS_DRIVER_REPLY_FETCH` — a ring-3 driver's reply and its next fetch in
/// one trap (RFC-0041 §D). `a0 = kind`, `a1 = reply_ptr` (a `DriverReply`, or
/// 0 when no reply is owed), `a2 = req_ptr` (room for a `DriverRequest`).
///
/// `0`: the reply, if any, was published and a request was written. `-1`: the
/// reply, if any, was published and no request is pending. Any other return
/// did nothing (no reply published, no request taken), so the caller still
/// holds its reply: `-99` for a task that is not the kind's driver, `-3` for a
/// reply that cannot be read or published, `-4` for a request buffer that is
/// null or not writable.
pub const SYS_DRIVER_REPLY_FETCH: u64 = 581;

/// `SYS_DRIVER_REPLY_WAIT` — [`SYS_DRIVER_REPLY_FETCH`] that BLOCKS while the
/// queue is empty, instead of returning `-1` for the driver to poll. `a0 =
/// kind`, `a1 = reply_ptr` (or 0), `a2 = req_ptr`, `a3` = the longest park in
/// milliseconds (0 = the kernel's default, clamped to 1000).
///
/// `0`: the reply, if any, was published and a request was written. `-1`: the
/// reply, if any, was published and no request arrived before the park ended
/// (call again). Every other return did nothing, exactly as 581: `-99`, `-3`,
/// `-4`. A request queued by an in-kernel client wakes the parked driver.
pub const SYS_DRIVER_REPLY_WAIT: u64 = 610;

/// `SYS_IPC_FAST_CALL_EP` — fast IPC addressed by a **capability** rather than
/// by a TID (RFC-0040 gap 2, stage 2). `a0` = a `Cap<Endpoint>` handle,
/// `a1..a4` = the four message words, exactly as `SYS_IPC_FAST_CALL`.
///
/// **What it changes.** `SYS_IPC_FAST_CALL` (108) takes a raw TID and checks
/// only that the destination is alive and is not the caller — no authority at
/// all, so any task granted 108 can call any task in the system. This one
/// resolves `a0` through the caller's own capability table, demanding `WRITE`
/// on a `Cap<Endpoint>`, and calls the task serving that endpoint. A caller
/// holding no endpoint capability can reach nothing, which is the property
/// 108 never had.
///
/// The resolution is `cap_store::get`, so it is also refused with
/// `-ECONTAINED` while RFC-0036 degraded mode is armed: a contained task may
/// still report on the console, but it may not open new service requests.
///
/// Returns what 108 returns — the generation-tagged exchange handle, or `-1` —
/// plus `-EPERM` when the capability does not resolve, carries no `WRITE`, or
/// names an endpoint no task serves yet. Those are one code on purpose: which
/// of them it was tells a caller about capabilities it does not hold.
///
/// 108 stood alongside this during the migration, as `SYS_OPEN` stood beside
/// `SYS_FILE_OPEN_TYPED`. Nothing on a board issues it any more, so it is now
/// behind `legacy-tid-ipc` and compiles out of every board build.
///
/// **`SYS_IPC_FAST_REPLY_ACCEPT` (580) does NOT retire with it**, and an
/// earlier version of this comment claimed it did. 580 is reply-then-accept:
/// it answers the exchange already in hand and then blocks for the next
/// request. It addresses **nobody** by TID, so there is no authority for a
/// capability to carry and nothing for 582 to replace. It is the server side
/// of the loop `vsbench` runs on the hot path, and it stays.
pub const SYS_IPC_FAST_CALL_EP: u64 = 582;

/// `SYS_ENDPOINT_CREATE_TYPED` — create an endpoint **owned by the caller**
/// and mint its `Cap<Endpoint>` into the caller's own table with `RW`.
///
/// No arguments. Returns the handle, or `-EMFILE` when the endpoint pool or
/// the caller's capability table is full.
///
/// # Why it exists (RFC-0040 gap 2 stage 4)
///
/// An endpoint's owner — the task that may `accept` on it — is fixed when its
/// capability is SEEDED, by image name. That makes a server necessarily an
/// exec'd image, and left two shapes unable to use capability-addressed IPC at
/// all: a `fork()`ed child serving another forked child, which is what
/// `userspace/tests/ipctest` phases B and E are. `endpoint_create_cap` had done
/// exactly this since RFC-0040 gap 1 and had **no caller**: the kernel could
/// create a caller-owned endpoint and nothing could ask it to.
///
/// # Minting, and why decision 3 still holds
///
/// This mints. Owner decision 3 (2026-09-03) keeps minting **boot-only or
/// create-only**, and this is the create-only half — the same shape as
/// [`SYS_PORT_CREATE_TYPED`], [`SYS_SHM_CREATE_TYPED`] and
/// [`SYS_SOCKET_TYPED`], which mint into their creator and confer no authority
/// over anything that existed before the call. The creator becomes the server
/// of an endpoint nobody else can name yet; handing the calling half to
/// another task is a separate act, and the only way to do it is the capability
/// MOVE of this same stage.
///
/// It is in [`CAP_TYPED_SYSCALLS`] for the reason stated there: a minter in a
/// sandbox profile hands it the power to create authority, so no rule may skip
/// it by accident.
pub const SYS_ENDPOINT_CREATE_TYPED: u64 = 583;

/// `SYS_MOTOR_MOVE_TYPED` — `a0 = cap` (`Cap<Motor>`), `a1 = direction`
/// (0 forward, 1 backward, 2 brake, 3 coast), `a2 = speed_pct` (0..=100).
/// Requires `WRITE`. No pair rule: one wheel, as [`SYS_MOTOR_SPEED_TYPED`]
/// (560) and [`SYS_MOTOR_DIRECTION_TYPED`] (576) both are, and for the same
/// reason — the untyped ancestor this migrates authority-preserving from,
/// `SYS_MOTOR_SPEED` (232), took one wheel too.
///
/// # Why this exists alongside 560 and 576 rather than replacing either
///
/// 560 takes a speed but always drives `Forward`. 576 takes a direction —
/// including `Backward` — but always drives it at a kernel-fixed 50 % duty
/// (`crates/core/syscall/src/handlers.rs::motor_direction_reporting`,
/// `motor_set_reporting(id, d, 50)`). Neither typed call can express "back
/// up at 30 %": `userspace/services/reflex`'s obstacle-avoidance backup and
/// `userspace/services/brain_client`'s reverse path both go through 576 today and
/// both discard whatever magnitude they were actually asked for — audit
/// U11-12, "reflex stops running at a fixed 50 %". This is the
/// `(direction, speed)` call that closes that gap: one number for the pair
/// that used to need two calls and still couldn't express what a single
/// caller with both values could have said in one.
///
/// # Combined call, RFC-0041 §580..=589's own description
///
/// Placed in the block this file's own doc on [`SYS_NR_RESERVED_UPPER`]
/// already calls "RFC-0041's combined calls" — this is exactly that shape,
/// two arguments 560 and 576 each took separately, combined into one call
/// so a caller cannot even construct the "direction without magnitude" bug
/// 560/576 have.
///
/// In order, matching every other typed motor call in this file: a refused
/// capability (`-ECAPSTALE`/`-ECAPKIND`/`-ECAPPERMS`, one
/// `SAFETY_CAP_DENIED_TYPED` record); a direction outside `0..=3` or a
/// `speed_pct` over 100 answers `-EINVAL` before anything reaches the motor
/// layer, no record, no pin written; otherwise
/// `azos_robot::motor_set_reporting(id, dir, speed_pct)` decides — the
/// halt rule (e-stop latched / containment armed) and `gate_speed`'s
/// envelope are that function's, not this call's, and are not restated
/// here. Handler: `crates/core/syscall/src/motor_cmd.rs::sys_motor_move_typed`.
pub const SYS_MOTOR_MOVE_TYPED: u64 = 584;

/// `SYS_SLEEP_UNTIL` — block until an absolute deadline (RFC-0044). `a0` =
/// nanoseconds on the RISC-V `time` counter, converted to ticks rounding up
/// (`crate::time::ns_to_ticks_ceil`).
///
/// `0`: the caller blocked and the counter has reached the deadline. `1`: the
/// deadline had already passed at entry; the caller did not block.
pub const SYS_SLEEP_UNTIL: u64 = 590;

/// `SYS_LINK_KEY_READ_TYPED` — U06-9 for `brain_client` (owner decision,
/// 2026-09-26): the ring-3 door onto the reserved-sector brain-link PSK.
///
/// `a0 = cap` (`Cap<LinkKey>`), `a1 = out_ptr`, `a2 = out_len`. Requires
/// `READ`. `Cap<LinkKey>` is a singleton, like `Cap<Buzzer>`: one brain-link
/// key per board, resource always `0`.
///
/// In order: a refused capability answers `-ECAPSTALE`/`-ECAPKIND`/
/// `-ECAPPERMS` (one `SAFETY_CAP_DENIED_TYPED` record); `out_len` under
/// [`LINK_KEY_READ_BYTES`] answers `-EINVAL` before the reserved sector is
/// touched; a missing hook or an absent/all-zero key answers `-EAUTH` — the
/// same "no plaintext fallback" outcome `brain_client`'s
/// FATAL-and-refuse-to-run already gave when `/fat/LINK.KEY` was missing,
/// now from inside the syscall instead of a FAT read; otherwise
/// [`LINK_KEY_READ_BYTES`] bytes are copied to `out_ptr` and that count is
/// returned. Handler: `crates/core/syscall/src/link_key.rs::sys_link_key_read_typed`.
pub const SYS_LINK_KEY_READ_TYPED: u64 = 591;

/// Bytes [`SYS_LINK_KEY_READ_TYPED`] copies on success: the brain-link PSK.
/// Named distinctly from `crates/core/syscall/src/link_key.rs::LINK_KEY_BYTES` —
/// same value (32), restated here because `crates/core/abi` cannot depend on
/// `crates/core/syscall` (the dependency runs the other way).
pub const LINK_KEY_READ_BYTES: usize = 32;

/// `SYS_NOTIFY_WAIT` — `a0 = uaddr`, `a1 = expected`, `a2 = timeout_ns`.
/// Sleeps while the `u32` at `uaddr` still holds `expected`: a futex-shaped
/// wait. `uaddr` must be 4-byte aligned and inside a shared-memory region the
/// caller has MAPPED (`SYS_SHM_MAP_TYPED`); the kernel keys the waiter by
/// (region, offset), never by an address, so two tasks that map one region
/// at different addresses meet on the same word. `timeout_ns`: `u64::MAX` =
/// none, `0` = do not block.
///
/// `0` woken by [`SYS_NOTIFY_WAKE`]; `1` the timeout passed (or, with `0`,
/// the word holds `expected`); `-EAGAIN` the word did not hold `expected`;
/// `-EINVAL` misaligned or `expected` wider than 32 bits; `-EFAULT` not in a
/// mapping of the caller's; `-ENOSPC` no waiter row; `-EBUSY` the scheduler
/// refused to block. Wave 6.
///
/// Not in [`CAP_TYPED_SYSCALLS`]: it takes no handle. The authority is the
/// caller's recorded mapping, which only a `Cap<Shm>` with `READ` creates —
/// see `crates/core/ipc/src/notify.rs` for why the handle itself is not the key
/// (capabilities move; the creator keeps the mapping and loses the handle).
///
/// `a1[32..]` must be 0 (`-EINVAL`): the robust register/drop ops that sat
/// there for one integration round (wave 11, LEASE2) are
/// [`SYS_NOTIFY_ROBUST`] (612). A wait ended because the word's owner died
/// answers [`NOTIFY_WAIT_OWNER_DIED`] (`2`).
pub const SYS_NOTIFY_WAIT: u64 = 592;

/// [`SYS_NOTIFY_ROBUST`] op: register the word at `uaddr` as a
/// robust lock word of the caller (owner-died, the robust-futex analogue).
/// When the caller exits or execs while the word's low 30 bits hold its TID,
/// the kernel replaces them with [`ROBUST_OWNER_DIED`] (keeping
/// [`ROBUST_WAITERS`]) and wakes every waiter on the word with
/// [`NOTIFY_WAIT_OWNER_DIED`]. `0`; `-EINVAL` misaligned or a TID wider than
/// [`ROBUST_TID_MASK`]; `-EFAULT` not in a mapping of the caller's;
/// `-EACCES` the region is read-only; `-EQUOTA` the caller already
/// registers its share of the table; `-ENOSPC` the table is full.
/// Registering a word twice is one registration.
pub const NOTIFY_ROBUST_ADD: u64 = 1;
/// [`SYS_NOTIFY_ROBUST`] op: drop a robust registration. `0`, or `-ENOENT`.
pub const NOTIFY_ROBUST_DEL: u64 = 2;
/// [`SYS_NOTIFY_WAIT`] return: the waiter was woken because the task holding
/// the (robust) word exited or exec'd while holding it.
pub const NOTIFY_WAIT_OWNER_DIED: i64 = 2;
/// Robust word layout (Linux's `FUTEX_TID_MASK`): the owner's TID.
pub const ROBUST_TID_MASK: u32 = 0x3FFF_FFFF;
/// Robust word layout (Linux's `FUTEX_OWNER_DIED`): the last owner died
/// holding the word. Written only by the kernel's exit sweep; cleared by the
/// next owner's acquire.
pub const ROBUST_OWNER_DIED: u32 = 0x4000_0000;
/// Robust word layout (Linux's `FUTEX_WAITERS`): someone may be asleep on the
/// word, so an unlock must wake.
pub const ROBUST_WAITERS: u32 = 0x8000_0000;

/// `SYS_NOTIFY_WAKE` — `a0 = uaddr`, `a1 = n`. Wakes up to `n` tasks waiting
/// in [`SYS_NOTIFY_WAIT`] on the same (region, offset) and returns how many;
/// `-EINVAL` / `-EFAULT` as the wait. Wave 6.
pub const SYS_NOTIFY_WAKE: u64 = 593;

/// `SYS_VDSO_TASK_MAP` — no arguments. Maps the caller's own per-task vDSO
/// page read-only into its shm/MMIO window and returns the user address, or
/// `-EINVAL` (kernel caller) / `-ENOMEM` (no frame or no window room).
/// Idempotent while the mapping stands; a forked child does not inherit it
/// (fork leaves the window out) and maps its own.
///
/// The page carries the caller's OWN counters — CPU time sampled at timer
/// interrupts, voluntary and preempted switches, the `ready_site` tag of its
/// last dispatch — and the latest value of each sensor it bound with
/// [`SYS_VDSO_SENSOR_BIND`], all under a seqlock, refreshed by the timer
/// interrupt while the task runs. Layout: `crates/core/libsys/src/pure.rs`
/// (`VTP_*`), asserted by `crates/core/mm/src/vdso.rs`. Wave 6.
pub const SYS_VDSO_TASK_MAP: u64 = 594;

/// `SYS_VDSO_SENSOR_BIND` — `a0 = cap` (`Cap<Sensor>`). Requires `READ`, the
/// check [`SYS_SENSOR_READ_TYPED`] makes. Sets the bit for the sensor type
/// the capability names in the caller's per-task page, so the timer
/// interrupt publishes it there. `1`: published at every interrupt; `0`:
/// bound, but the type has no interrupt-safe source (only the encoder and
/// odometry have one) and its slot stays unpublished; `-ENOENT`: the caller
/// has not mapped its page ([`SYS_VDSO_TASK_MAP`]); the capability's
/// `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS`. Wave 6.
pub const SYS_VDSO_SENSOR_BIND: u64 = 595;

/// `SYS_ENTROPY_READ_TYPED` — ring-3 read of the kernel entropy pool (wave 9,
/// owner decision P9). `a0 = cap` (`Cap<Entropy>`), `a1 = out_ptr`,
/// `a2 = out_len`. Requires `READ`. `Cap<Entropy>` is a singleton like
/// `Cap<LinkKey>`: resource always `0`.
///
/// In order: a refused capability answers `-ECAPSTALE`/`-ECAPKIND`/
/// `-ECAPPERMS` (one `SAFETY_CAP_DENIED_TYPED` record); a null `out_ptr`,
/// `out_len == 0` or `out_len >` [`ENTROPY_READ_MAX`] answers `-EINVAL`
/// before the pool is touched; an unseeded pool answers `-ENODEV` and writes
/// nothing — no entropy source fed the pool at boot, and nothing seeds it
/// later in the same boot, so the answer does not change until a reboot with
/// a source (the first such refusal of a boot is recorded, see
/// `SAFETY_ENTROPY_UNSEEDED_REFUSED`); otherwise exactly `out_len` bytes from
/// the pool's HMAC-DRBG are copied to `out_ptr` and `out_len` is returned.
/// Handler: `crates/core/syscall/src/entropy.rs::sys_entropy_read_typed`.
pub const SYS_ENTROPY_READ_TYPED: u64 = 596;

/// Largest `out_len` [`SYS_ENTROPY_READ_TYPED`] accepts: 256 bytes, the
/// `getentropy(3)` bound. The pool is filled under a plain spin lock with
/// preemption off; 256 bytes is 8 HMAC-DRBG output blocks per call, and a
/// caller that needs more calls again.
pub const ENTROPY_READ_MAX: usize = 256;

// ── The rest of the RFC-0048 P2 file surface (owner round 23) ─────────────
//
// Numbered NOW rather than when a native ext4 arrives (owner decision, round
// 23, against "wait for ext4"). 597..=601: the next unused numbers after
// wave 9's `SYS_ENTROPY_READ_TYPED` (596), so `SYS_NR_RESERVED_UPPER` grows
// to 602 as its own doc requires (250..=269, the filesystem block, has no
// five free numbers left). Paths are NUL-terminated
// and copied as `SYS_STAT`'s is; the result is `0` or a negative errno
// (`azos_abi::error::Errno`); `-1` means no filesystem is installed, as
// for every other file call. `SYS_FSYNC_TYPED` names its file by a
// capability. Since wave 10 `SYS_RMDIR`, `SYS_RENAME` and `SYS_TRUNCATE`, like
// `SYS_MKDIR`/`SYS_UNLINK`, need a `Cap<File>` with WRITE naming a directory
// tree that covers the path (minted only by the topology, kind `"file"`,
// target the tree's absolute root): `-EACCES` without one, `-EINVAL` for a
// relative path or one with a `.`/`..` component. `SYS_STATFS` needs none.

/// `SYS_RMDIR` — `a0 = path`. Remove an empty directory. `-ENOTEMPTY` when it
/// is not empty, `-ENOTDIR` when it is a file, `-ENOENT` when it is missing.
pub const SYS_RMDIR: u64 = 597;
/// `SYS_RENAME` — `a0 = from`, `a1 = to`. Within one mounted filesystem;
/// across two, `-EINVAL`.
pub const SYS_RENAME: u64 = 598;
/// `SYS_TRUNCATE` — `a0 = path`, `a1 = length` (all 64 bits). Set a file's
/// size, dropping or zero-filling its tail. Its tree capability may name the
/// file itself; the other tree calls need the path strictly under the root.
pub const SYS_TRUNCATE: u64 = 599;
/// `SYS_FSYNC_TYPED` — `a0 = Cap<File>` (any permission). Make the writes
/// through that file durable: its buffered contents are written back and the
/// device flushed. `-ECAPSTALE`/`-ECAPKIND` for a bad handle, as every typed
/// file call answers.
pub const SYS_FSYNC_TYPED: u64 = 600;
/// `SYS_STATFS` — `a0 = path`, `a1 = buffer`, `a2 = its length` (at least
/// [`STATFS_BYTES`]). Capacity and free space of the filesystem `path` is on.
pub const SYS_STATFS: u64 = 601;

/// Bytes `SYS_STATFS` writes: all little-endian, at these offsets. A shorter
/// buffer is refused with `-EINVAL` and nothing is written.
///
/// | off | type | field |
/// |---|---|---|
/// | 0 | u32 | filesystem type (`1` FAT32, `2` tmpfs, `3` procfs, `0` the ramfs) |
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

// 596..=601 are allocated to other wave-9 fronts (entropy, FS2).

/// `SYS_IPC_LEASE_WAIT` — `a0 = cap` (`Cap<Lease>`, `READ`). The lessor blocks
/// until its lease is returned or expires, donating its priority to the lessee
/// for the span of the wait (RFC-0031 lease priority inheritance, reachable
/// from ring 3 since wave 9; a ring-3 lessee is lent at most the ring-3 floor,
/// 12). `0`: returned; `1`: expired (or the lessee exited); `-1`: the
/// capability names a lease that is free, or one the caller is not the lessor
/// of; the capability's `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS`. The
/// capability is minted by [`SYS_IPC_LEASE_GRANT_TYPED`] for a ring-3 lessor (find it
/// with `SYS_CAP_LOOKUP(CapKind::Lease, lease_id)`) and revoked by
/// [`SYS_IPC_LEASE_FREE`]. Wave 9.
pub const SYS_IPC_LEASE_WAIT: u64 = 602;

/// `SYS_IPC_LEASE_GRANT_TYPED` — `a0 = cap` (`Cap<Shm>`, `READ`), `a1 =
/// lessee_tid` (low 32 bits), `a2 = expire_ticks` (0 = none). Grants the region
/// the capability names to the lessee and returns the lease id. For a ring-3
/// lessor it also mints a `Cap<Lease>` (resource = the lease id, `READ`) into
/// the caller's table — the authority [`SYS_IPC_LEASE_WAIT`] checks; with no
/// room for it the grant is undone and -1 returned. Refusals: the
/// capability's `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS` (one
/// `SAFETY_CAP_DENIED_TYPED` record; a capability whose region was released
/// is stale); `-EQUOTA` when the caller already occupies `MAX_LEASES / 2`
/// entries of the lease table (every entry naming it as lessor that is not
/// free, until it calls `SYS_IPC_LEASE_FREE`; kernel callers exempt); -1 when
/// the table is full. Replaces the raw-id 111 (retired 2026-09-28).
///
/// **Grant flags in `a1[32..]` (wave 11, LEASE3).** [`LEASE_GRANT_SEAL`]: the
/// producer-side write seal — the caller's own mapping of the region becomes
/// read-only (TLB shot down on every hart) until the lease ends, and gets its
/// write back then; a write in between faults and kills the caller
/// ([`EXIT_STAT_LEASE_SEAL_FAULTS`]). Any other bit there is `-EINVAL`. A
/// topology row with `lease_seal = true` must pass it: an unsealed grant from
/// such a task is `-EACCES`. The high half was narrowed away before; a
/// zero-extended TID (every libsys caller) is unchanged.
pub const SYS_IPC_LEASE_GRANT_TYPED: u64 = 603;
/// [`SYS_IPC_LEASE_GRANT_TYPED`] flag in `a1`: seal the lessor's own mapping
/// for the life of the lease.
pub const LEASE_GRANT_SEAL: u64 = 1 << 32;

/// `SYS_PORT_WAIT_UNTIL_TYPED` — `a0 = cap` (`Cap<Port>`), `a1 = out_ptr`,
/// `a2 = deadline` (absolute nanoseconds on the time counter, the unit of
/// [`SYS_SLEEP_UNTIL`]; `u64::MAX` = none; any instant already passed, 0
/// included, polls). Wave 11 (PORTWAIT), RFC-0052 §6.3.
///
/// The multi-source wait: sleeps until any source bound to the port has an
/// event (an IRQ, a channel message, an io_ring completion, a timer source's
/// deadline) or the deadline passes, whichever is first. Writes the event
/// through `a1` in [`SYS_PORT_POLL_TYPED`]'s 16-byte layout (key `u64`,
/// source type `u8` at byte 8, source id `u32` at byte 12) and returns 16,
/// or returns 0 with nothing written when the deadline passed first. A new
/// number rather than a third argument on [`SYS_PORT_WAIT_TYPED`] (577),
/// whose callers leave `a2` unset. Unlike 577 the number of wakes is not
/// bounded: the deadline bounds the wait. Requires `READ`, which containment
/// leaves live. In order: `-EINVAL` for a null `a1`; the capability's
/// `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS`; `-EFAULT` when the 16 bytes at
/// `a1` are not writable user memory, checked before anything is taken;
/// `-ECAPSTALE` at once when the port is destroyed before or during the wait;
/// `-EMFILE` when eight tasks already wait on the port; `-EBUSY` when the
/// scheduler refused to block (preemption disabled) and nothing was ready.
pub const SYS_PORT_WAIT_UNTIL_TYPED: u64 = 604;

/// `SYS_EXIT_STATS` — `a0 = which` (an `EXIT_STAT_*` selector). Returns that
/// exit-path counter, a total since boot over every task, or `-EINVAL` for an
/// unknown selector. Read-only, no capability: the counts say how address
/// spaces were torn down, not whose. Wave 11 (EXIT2): the exit notice is
/// published after the exiting task's teardown, and these are what a test
/// reads to see that it was.
pub const SYS_EXIT_STATS: u64 = 605;
/// [`SYS_EXIT_STATS`] selector: address spaces torn down on their own task's
/// exit path.
pub const EXIT_STAT_EXIT_TEARDOWNS: u64 = 0;
/// [`SYS_EXIT_STATS`] selector: address spaces the slot-reuse fallback found
/// still allocated on a slot being claimed (its owner's exit did not release
/// them).
pub const EXIT_STAT_REUSE_TEARDOWNS: u64 = 1;
/// [`SYS_EXIT_STATS`] selector: exit notices published while the exiting
/// task still held its address space.
pub const EXIT_STAT_EARLY_NOTICES: u64 = 2;
/// [`SYS_EXIT_STATS`] selector (wave 11, LEASE2): user faults the kernel
/// attributed to a lease mapping it had already revoked (a lessee touching
/// its buffer after return, expiry, or the lessor's free). The task is killed
/// as for any unresolved fault; this counts the kills that were a lease.
pub const EXIT_STAT_LEASE_REVOKED_FAULTS: u64 = 3;
/// [`SYS_EXIT_STATS`] selector (wave 11, LEASE3): lessor writes that faulted
/// on its own mapping of a buffer it had granted with [`LEASE_GRANT_SEAL`].
/// The task is killed as for any unresolved fault; this counts those kills.
pub const EXIT_STAT_LEASE_SEAL_FAULTS: u64 = 4;
/// [`SYS_EXIT_STATS`] selector (wave 12, EXIT2): exit notices that found no
/// room and were lost. Zero by construction — notices are kept until reaped,
/// in a table with one entry per task slot behind a creation admission — so
/// any other count is a bug.
pub const EXIT_STAT_NOTICE_DROPS: u64 = 5;
/// [`SYS_EXIT_STATS`] selector (wave 12, EXIT2): `fork`/`spawn` refusals
/// because queued (unreaped) exit notices hold the task slots that were free.
pub const EXIT_STAT_NOTICE_REFUSALS: u64 = 6;

/// `SYS_SENSOR_READ_TS` — `a0 = cap` (`Cap<Sensor>`, `READ`), `a1 = out_ptr`,
/// `a2 = out_len`. The read [`SYS_SENSOR_READ_TYPED`] makes, with the time the
/// value was ACQUIRED: a `azos_abi::sensor_sample` header
/// (`SENSOR_SAMPLE_HDR_LEN` bytes: version, header length, flags, payload
/// length, `acq_ns` on the vDSO clock) followed by 561's bytes for the type.
/// Returns header + payload bytes; `0` when 561 would return 0 (no data, and
/// nothing is written); `-1` when `out_len` cannot hold the header and the
/// payload (refused, never truncated) or the device did not answer; the
/// capability's `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS`.
///
/// A number of its own rather than a versioned 561: 561 has no spare argument
/// an old image is known to zero, so its bytes stay exactly what every
/// existing binary parses. Wave 11 (SENSORTS).
pub const SYS_SENSOR_READ_TS: u64 = 606;

// ---------------------------------------------------------------------------
// The user shell (RFC-0055, wave 11): pipes, spawn with arguments and a move
// list, the console wait, and a stop request to a descendant. Layouts and
// flag values are in `crate::ushell`.
// ---------------------------------------------------------------------------

/// `SYS_PIPE_TYPED` — `a0 = *mut [u32; 2]`, `a1 = flags` (`PIPE_NONBLOCK`).
/// Allocates a pipe and mints two `Cap<Pipe>` handles into the CALLER's own
/// table: `out[0]` the read end (`READ`), `out[1]` the write end (`WRITE`),
/// both carrying `DUP` so the `SYS_SPAWN_EX` move list can hand them to a
/// child. Returns 0, `-EFAULT` (unwritable `a0`), `-EMFILE` (no room in the
/// caller's table for two handles), `-ENOSPC` (pool full), `-EQUOTA` (the
/// caller already holds `MAX_PIPES / 2` pipes it created), `-EINVAL` (unknown
/// flag). Read, write and close are 564/565/566, which dispatch on the
/// handle's kind: a read of an empty pipe with a live writer blocks (or
/// answers `-EAGAIN` with `PIPE_NONBLOCK`), 0 is end-of-file; a write of at
/// most `PIPE_ATOMIC` bytes is all-or-block, `-EPIPE` when no reader is left;
/// both blocks end with `-EINTR` on a stop request. A pipe lives as long as a
/// handle to either end does, in any table.
pub const SYS_PIPE_TYPED: u64 = 607;

/// `SYS_SPAWN_EX` — `a0 = path`, `a1 = *const SpawnReq` (0: exactly
/// `SYS_SPAWN`). `SYS_SPAWN`'s machinery (digest-bound profile, topology row,
/// class, budget, capabilities) plus: the caller must hold a `Cap<Launch>`
/// with `EXEC` for the image the digest resolves to; argv, environment and a
/// working directory written into the child as a `StartupBlock` whose
/// address the child receives in `a1` (`x1`) — not `a0`, which the spawn
/// hand-off zeroes as fork's does; a move list (at most 8) that MOVES the
/// caller's `Cap<File>` descriptors or `Cap<Pipe>` ends into the child as its
/// fds 0..7, rights kept or lowered, never raised; `SPAWN_F_DIE_WITH_PARENT`.
/// Returns the child's TID, or `-EACCES` (no profile, no row, no launch
/// grant), `-ECAPKIND`, `-ECAPPERMS`, `-ECAPSTALE`, `-EMFILE`, `-EINVAL`
/// (version, limits, unknown flag), `-EFAULT`, `-1` as `SYS_SPAWN`. Nothing
/// moves unless the child is released.
pub const SYS_SPAWN_EX: u64 = 608;

/// `SYS_CONSOLE_WAIT` — `a0 = buf`, `a1 = len`, `a2 = timeout_ns`
/// (`u64::MAX` none, 0 poll), `a3 = 0`. One blocking wait over console input
/// and the caller's children's exits. `n > 0`: raw bytes copied out (no echo,
/// no editing); 0: timeout; `-EINTR`: an exit notice is pending for the
/// caller (reap it with 559/562 and call again) or a stop request arrived;
/// `-EBUSY`: another task owns console input; `-EFAULT`; `-EINVAL` (`a3`).
/// The first call with `len > 0` makes the caller the console's one input
/// owner until it exits. Untyped on purpose, like `SYS_WRITE`: the seccomp
/// profile is the authority, and only the shell's lists it.
pub const SYS_CONSOLE_WAIT: u64 = 609;

/// `SYS_TASK_KILL` — `a0 = tid`, `a1 = how` (`KILL_REQUEST` | `KILL_FORCE`),
/// `a2 = signo` (1..=31), `a3 = flags` (`KILL_SUBTREE`). The caller must be
/// an ANCESTOR of `tid` (parent chain, at most 8 steps); anything else,
/// absent included, is `-ESRCH`; self is `-EINVAL`. A request wakes the
/// target's interruptible waits with `-EINTR`; force also ends it at its next
/// return to user mode (or at that wake) with exit code `128 + signo`, by the
/// path a user-mode fault takes, never inside a syscall. Returns how many
/// tasks were signalled (at least 1).
pub const SYS_TASK_KILL: u64 = 611;

/// `SYS_NOTIFY_ROBUST` — `a0 = uaddr`, `a1 = op` ([`NOTIFY_ROBUST_ADD`] or
/// [`NOTIFY_ROBUST_DEL`]). Registers or drops the caller's robust lock word
/// at `uaddr` (the owner-died protocol; the word layout is
/// [`ROBUST_TID_MASK`] / [`ROBUST_OWNER_DIED`] / [`ROBUST_WAITERS`], waits on
/// it are [`SYS_NOTIFY_WAIT`]). `uaddr` is resolved as `SYS_NOTIFY_WAIT`
/// resolves it: 4-byte aligned, inside a shared-memory region the caller has
/// mapped. Any other `op` is `-EINVAL`; the other codes are the ops'. Untyped
/// for the reason `SYS_NOTIFY_WAIT` is: the authority is the caller's
/// recorded mapping. Wave 11 (LEASE3): the ops rode in `SYS_NOTIFY_WAIT`'s
/// `a1[32..]` for one integration round; that encoding is `-EINVAL` now.
pub const SYS_NOTIFY_ROBUST: u64 = 612;

/// `SYS_IPC_LEASE_ACCEPT_MAP` — `a0 = lessor_tid`, `a1 = *mut u64`. The accept
/// [`SYS_IPC_LEASE_ACCEPT`] makes (same lessor rule, same bounded wait), then
/// the kernel maps the leased region into the caller (writable only when the
/// region is read-write and the lessor's capability held `WRITE` at grant),
/// writes the mapping's address through `a1` and returns the lease id. The
/// mapping belongs to the lease: when the lease ends (return, expiry, the
/// lessor's free or exit) the kernel removes it from the lessee's page table
/// and shoots the range down on every hart, so a later access faults, is
/// recorded ([`EXIT_STAT_LEASE_REVOKED_FAULTS`]) and kills the lessee. An
/// expired lease is revoked by the kernel's lease worker without the
/// lessor's help. `-EFAULT` `a1` unwritable (checked before accepting);
/// `-EINVAL` a kernel caller or `a0 > u32::MAX`; `-ENOMEM` no address or
/// holder room (the lease is returned); `-1` as the plain accept, or the
/// lease ended before its mapping was recorded. Wave 11 (LEASE3): replaces
/// the accept flag in `SYS_IPC_LEASE_ACCEPT`'s `a0` bit 32.
pub const SYS_IPC_LEASE_ACCEPT_MAP: u64 = 613;

/// `SYS_POWER_TYPED` — `a0 = Cap<Power>` handle, `a1 = op` (`crate::power`:
/// `POWER_OP_SUSPEND`, `POWER_OP_REBOOT`, `POWER_OP_SHUTDOWN`,
/// `POWER_OP_SCHED_HZ_GET`, `POWER_OP_SCHED_HZ_SET`), `a2` = the operation's
/// argument (`SCHED_HZ_SET`: the rate, `POWER_SCHED_HZ_MIN..=POWER_SCHED_HZ_MAX`;
/// otherwise 0). RFC-0055 S5: the first privileged family with a ring-3 form,
/// for the `POWER.ELF` tool. The capability is checked FIRST, before the
/// operation is even decoded: `WRITE` for every operation but
/// `SCHED_HZ_GET`, which needs `READ`; a refusal is recorded
/// (`SAFETY_CAP_DENIED_TYPED`). Returns 0 (suspend: after the resume;
/// reboot/shutdown do not return), the rate (`SCHED_HZ_GET`), `-EINVAL`
/// (unknown op, a rate out of range, a non-zero argument), or the
/// capability's `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS`. Reboot and
/// shutdown are orderly: the boot's unconfirmed mark is voided and deferred
/// console lines are flushed first, as 270/271 do.
///
/// Numbering: wave 11 fronts were handed 612..=614; LEASE3 has 612 and 613,
/// so the power family is 614.
pub const SYS_POWER_TYPED: u64 = 614;

/// `SYS_FLIGHT_TYPED` — `a0 = Cap<Motor>`, `a1 = op`
/// (`azos_abi::families::FLIGHT_OP_*`). The ring-3 form of the recovery
/// console's `flight arm` / `flight disarm`, for the `FLIGHT.ELF` tool (wave
/// 12, RFC-0055 S5). Pair-wide: `WRITE` on the presented capability and on
/// both wheels in the caller's table, checked FIRST; a refusal is recorded.
/// Returns 0, `-EINVAL` (unknown op, non-zero `a2`), `-ENOSYS` (an image
/// without the Robot domain), or the capability's `-ECAPSTALE` /
/// `-ECAPKIND` / `-ECAPPERMS`.
pub const SYS_FLIGHT_TYPED: u64 = 615;

/// `SYS_BEHAVIOR_TYPED` — `a0 = Cap<Power>`, `a1 = op`, `a2 = layer`
/// (`families::BEHAVIOR_OP_*`): `behavior enable|disable <layer>` and the
/// enabled-layer mask, for `BEHAVIOR.ELF` (wave 12). `WRITE` to switch,
/// `READ` to read. Returns 0 / the mask, `-EINVAL` (unknown op, layer 0 or
/// out of range), `-ENOSYS` (no Robot domain), or the capability's errno.
pub const SYS_BEHAVIOR_TYPED: u64 = 616;

/// `SYS_CONFIG_TYPED` — `a0 = Cap<Power>`, `a1 = op`, `a2/a3 = key`,
/// `a4/a5 = value buffer` (`families::CONFIG_OP_*`): `config get|set`, for
/// `CONFIG.ELF` (wave 12). `READ` to get, `WRITE` to set any key. Returns the
/// value's length / 0, `-ENOENT`, `-EINVAL` (lengths, a buffer shorter than
/// the value, unknown op), `-EFAULT`, `-ENOSPC` (table full), `-ENOSYS`, or
/// the capability's errno.
pub const SYS_CONFIG_TYPED: u64 = 617;

/// `SYS_OTA_TYPED` — `a0 = Cap<Power>`, `a1 = op` (`families::OTA_OP_*`):
/// `ota status|rollback`, for `OTA.ELF` (wave 12). `READ` for the status
/// word, `WRITE` to roll back. Returns the word / 0 (rolled back) / 1
/// (already on the last good slot), `-EACCES` (that slot failed
/// verification), `-EINVAL`, `-ENOSYS`, or the capability's errno.
pub const SYS_OTA_TYPED: u64 = 618;
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
pub const SYS_THREAD_CREATE: u64 = 620;

/// `SYS_THREAD_EXIT` — wave 13: end only the calling thread, with `a0` as
/// its code (a thread's code is reported to nobody). Its clear-tid word is
/// cleared and woken. The process's last thread ending ends the process; a
/// process's first thread (its leader) that ends while others run waits in
/// the kernel for them and then reports. `SYS_EXIT` from any thread ends the
/// whole process (every other thread is stopped). Does not return.
pub const SYS_THREAD_EXIT: u64 = 621;

/// `SYS_FUTEX_WAIT` — wave 13: `a0` = address of an aligned 32-bit word,
/// `a1` = the value it must hold, `a2` = a relative timeout in nanoseconds
/// (0: none). Blocks while the word holds `a1` until a [`SYS_FUTEX_WAKE`]
/// on the same word by a thread of the same process, the timeout, or a stop.
/// Returns 0 (woken), `-EAGAIN` (the word differs), `-ETIMEDOUT` (110),
/// `-EINTR`, `-EFAULT`.
pub const SYS_FUTEX_WAIT: u64 = 622;

/// `SYS_FUTEX_WAKE` — wave 13: wake at most `a1` threads of the calling
/// process waiting on the word at `a0`. Returns how many were woken.
pub const SYS_FUTEX_WAKE: u64 = 623;

/// Most live threads of one process (the leader included); see
/// [`SYS_THREAD_CREATE`].
pub const GROUP_THREADS_MAX: u64 = 16;
/// Most processes with more than one live thread at once.
pub const GROUPS_MAX: u64 = 8;

/// `SYS_MODULE_VERIFY` — RFC-0053 stage L0b, the first half of loading a
/// relocatable module (`.ko`) into a ring-3 server. `a0` = pointer to the
/// module FILE bytes, `a1` = their length (at most [`MODULE_MAX_BYTES`]),
/// `a2` = pointer to the module's 8.3 name on the boot volume (e.g.
/// `LXTEST.KO`, no NUL), `a3` = the name's length.
///
/// The kernel hashes the bytes (SHA-256) and looks the name up in the module
/// digest table built into the kernel image (`build/module_hashes*.rs`). On a
/// match it returns a one-shot token (`> 0`) bound to the caller's TID and
/// to the module's length; otherwise `-EPERM`, and the refusal is recorded
/// (a count and a console line). `-EFAULT` for unreadable memory, `-EINVAL`
/// for a length or name out of range. Only in a kernel built with the
/// `lx-loader` feature (Kconfig `LINUX_DRIVERS` + `LX_SERVER_SKELETON`);
/// elsewhere the number is unassigned (`-ENOSYS`).
///
/// Numbering: wave 12 left 615..=629 to the fronts that add typed families
/// (615..=618 taken); the module pair takes 630/631 so no merge renumbers it.
pub const SYS_MODULE_VERIFY: u64 = 630;

/// `SYS_MODULE_MAP_X` — RFC-0053 stage L0b, the second half: `a0` = token
/// from [`SYS_MODULE_VERIFY`], `a1` = page-aligned start of the caller's
/// relocated text, `a2` = its length. The token is consumed whatever the
/// outcome (one attempt per verification). The kernel checks the token is
/// live and the caller's, that the range is at most the verified module's
/// length rounded up to a page, and that every page in it is the caller's
/// own anonymous read-write page (not shared memory, not copy-on-write,
/// not already executable); then flips each page read-write -> read-execute
/// (never both) and synchronises the instruction cache on every hart.
/// `0` on success, `-EPERM` for a bad token, `-EINVAL` for a range the
/// checks refuse (nothing is changed then).
pub const SYS_MODULE_MAP_X: u64 = 631;

/// `SYS_TASK_SUBREAPER` (wave 13) — `a0 = op`: [`SUBREAPER_GET`] (0),
/// [`SUBREAPER_SET`] (1) or [`SUBREAPER_CLEAR`] (2). Marks the caller a child
/// subreaper, as Linux `prctl(PR_SET_CHILD_SUBREAPER)`: when a task exits,
/// its children (and the exit notices of its children not yet reaped) go to
/// the nearest live ancestor so marked, else to the autorun image's task
/// (init), and that task's `waitpid`/`wait_status` reaps them. Returns the
/// mark after the operation (0 or 1), `-EINVAL` for another `op`. The mark is
/// the task's own and is not inherited by a child.
pub const SYS_TASK_SUBREAPER: u64 = 619;
/// [`SYS_TASK_SUBREAPER`] op: read the mark.
pub const SUBREAPER_GET: u64 = 0;
/// [`SYS_TASK_SUBREAPER`] op: mark the caller.
pub const SUBREAPER_SET: u64 = 1;
/// [`SYS_TASK_SUBREAPER`] op: clear the mark.
pub const SUBREAPER_CLEAR: u64 = 2;

/// Largest module `SYS_MODULE_VERIFY` hashes: 4 MiB. Linux's ext4.ko with
/// debug info stripped is about 1 MiB on these ISAs [est.]; the bound keeps
/// one call's kernel time bounded.
pub const MODULE_MAX_BYTES: u64 = 4 << 20;

/// Reserved upper bound. Numbers ≥ this are unallocated; new syscalls
/// must increment this and request an RFC. The 528..=549 range is
/// reserved for cap-typed migrations of the IPC family (W5);
/// 550..=579 extends it for the hardware caps that didn't fit
/// (W5 batches 5.4+) and for `Cap<File>` and `Cap<Socket>`; 573..=578 in it
/// are RFC-0040 gap 1's typed forms. 580..=589 holds RFC-0041's combined
/// calls. 590..=603 takes calls outside those families, in RFC order
/// (597..=601 the owner-round-23 file calls, 602 the lease wait, 603 the
/// typed lease grant). Wave 9 was handed 596..=614; 605 is `SYS_EXIT_STATS`
/// (wave 11), 610 is `SYS_DRIVER_REPLY_WAIT`, and 607, 608, 609 and 611 are the
/// user shell's (RFC-0055, wave 11); 612 (`SYS_NOTIFY_ROBUST`) and 613
/// (`SYS_IPC_LEASE_ACCEPT_MAP`) the lease front's (wave 11, LEASE3); 614 the
/// shell's power family (`SYS_POWER_TYPED`). 604 and
/// 606 belong to other wave-11 fronts. Wave 12: 615..=618 the flight,
/// behavior, config and OTA families (`azos_abi::families`); 630 and 631
/// the module loader's (RFC-0053 L0b, `SYS_MODULE_VERIFY`/`SYS_MODULE_MAP_X`),
/// the highest numbers in use. Wave 13: 619 `SYS_TASK_SUBREAPER`, 620..=623 the
/// native thread calls (`SYS_THREAD_CREATE`, `SYS_THREAD_EXIT`,
/// `SYS_FUTEX_WAIT`, `SYS_FUTEX_WAKE`), 624..=629 the signal calls.
pub const SYS_NR_RESERVED_UPPER: u64 = 632;

// ---------------------------------------------------------------------------
// The Cap<T> families, as a set.
// ---------------------------------------------------------------------------

/// Every syscall belonging to a `Cap<T>` family.
///
/// **Membership is family, not number range**, and the difference is the whole
/// reason this exists rather than a `(528..=561).contains(n)` helper. Three
/// numbers sit inside that range and are NOT members:
///
///   * [`SYS_CAP_LOOKUP`] (558) — capability *discovery*. It takes no cap; it
///     is how a task finds the handles it will later pass.
///   * [`SYS_WAIT_STATUS`] (559) and [`SYS_WAITPID`] (562) — process
///     lifecycle, which landed in the same block only because that is where
///     the free numbers were.
///
/// A range predicate would sweep all three in, and every rule keyed on this
/// set would then be making claims about calls it does not describe.
///
/// **Members are not uniform, either**, and a reader deciding policy from this
/// list must know it. Most take `a0 = cap_handle` and are therefore *narrower*
/// than an untyped equivalent. Six MINT a capability instead of consuming
/// one — [`SYS_PORT_CREATE_TYPED`] (no args at all),
/// [`SYS_SHM_CREATE_TYPED`] (`a0 = page_count`),
/// [`SYS_IORING_CREATE_TYPED`] (`a0 = out_ptr`),
/// [`SYS_FILE_OPEN_TYPED`] (`a0 = path_ptr`, `a1 = flags`),
/// [`SYS_SOCKET_TYPED`] and [`SYS_CHAN_CREATE_TYPED`] (no args). Granting a minter to a
/// sandbox profile hands it the power to create authority, which is the
/// opposite of the "typed is narrower" argument. They are in the set precisely
/// so a rule cannot skip them by accident.
///
/// The consumer today is `tests/host/seccomp-tests`, whose tripwire requires every
/// member a profile grants to carry a written justification. Kept here rather
/// than there because it is an ABI fact — which calls take capabilities — and
/// because syscall numbers live only in this file (gate check
/// `syscall-number literals`).
pub const CAP_TYPED_SYSCALLS: &[u64] = &[
    SYS_CHAN_WRITE_TYPED,        // 528
    SYS_CHAN_READ_TYPED,         // 529
    SYS_PORT_CREATE_TYPED,       // 530  mints
    SYS_PORT_POLL_TYPED,         // 531
    SYS_PORT_DESTROY_TYPED,      // 532
    SYS_SHM_CREATE_TYPED,        // 533  mints
    SYS_SHM_ACQUIRE_TYPED,       // 534
    SYS_SHM_RELEASE_TYPED,       // 535
    SYS_IORING_CREATE_TYPED,     // 536  mints
    SYS_IORING_SUBMIT_TYPED,     // 537
    SYS_IORING_DESTROY_TYPED,    // 538
    SYS_GPIO_READ_TYPED,         // 539
    SYS_GPIO_WRITE_TYPED,        // 540
    SYS_GPIO_SET_DIR_TYPED,      // 541
    SYS_I2C_READ_TYPED,          // 542
    SYS_I2C_WRITE_TYPED,         // 543
    SYS_I2C_DETECT_TYPED,        // 544
    SYS_PWM_ENABLE_TYPED,        // 545
    SYS_PWM_DISABLE_TYPED,       // 546
    SYS_PWM_SET_PERIOD_TYPED,    // 547
    SYS_PWM_SET_DUTY_TYPED,      // 548
    SYS_PWM_SET_DUTY_PCT_TYPED,  // 549
    SYS_MOTOR_SET_TARGET_TYPED,  // 550
    SYS_MOTOR_TICK_TYPED,        // 551
    SYS_MOTOR_ENABLE_TYPED,      // 552
    SYS_MOTOR_ENABLED_TYPED,     // 553
    SYS_MOTOR_SET_GAINS_TYPED,   // 554
    SYS_MOTOR_RESET_TYPED,       // 555
    SYS_DRIVER_REGISTER_TYPED,   // 556
    SYS_DRIVER_UNREGISTER_TYPED, // 557
    SYS_MOTOR_SPEED_TYPED,       // 560
    SYS_SENSOR_READ_TYPED,       // 561
    // The stamped read (wave 11), outside 528..=579 like 600.
    SYS_SENSOR_READ_TS,          // 606
    SYS_MOTOR_DIRECTION_TYPED,   // 576
    SYS_MOTOR_ANGLE_TYPED,       // 578
    SYS_FILE_OPEN_TYPED,         // 563  mints
    SYS_FILE_READ_TYPED,         // 564
    SYS_FILE_WRITE_TYPED,        // 565
    SYS_CLOSE_TYPED,             // 566
    // Takes a `Cap<File>` in `a0` (owner round 23), outside 528..=579.
    SYS_FSYNC_TYPED,             // 600
    SYS_SOCKET_TYPED,            // 567  mints
    SYS_CONNECT_TYPED,           // 568
    SYS_SEND_TYPED,              // 569
    SYS_RECV_TYPED,              // 570
    SYS_MCAST_JOIN_TYPED,        // 571
    SYS_MCAST_LEAVE_TYPED,       // 572
    SYS_CHAN_CREATE_TYPED,       // 573  mints
    SYS_SHM_MAP_TYPED,           // 574
    SYS_PORT_BIND_TYPED,         // 575
    SYS_PORT_WAIT_TYPED,         // 577
    // Not named `*_TYPED`, and a member all the same: membership is about
    // taking a capability in `a0`, not about the spelling. RFC-0040 gap 2.
    // No profile grants it yet — the userspace migration and its profile rows
    // are one commit, so the row and the caller land together — and listing it
    // here now is what arms the tripwire for the day one does.
    SYS_IPC_FAST_CALL_EP,        // 582
    // Mints, and takes no capability — a member for the reason the doc above
    // gives: minters are in this set precisely so a rule cannot skip them.
    SYS_ENDPOINT_CREATE_TYPED,   // 583  mints
    SYS_MOTOR_MOVE_TYPED,        // 584
    SYS_LINK_KEY_READ_TYPED,     // 591
    // Takes a `Cap<Sensor>` in `a0` (wave 6): a member by the rule above.
    SYS_VDSO_SENSOR_BIND,        // 595
    SYS_ENTROPY_READ_TYPED,      // 596
    // Takes a `Cap<Lease>` in `a0` (wave 9).
    SYS_IPC_LEASE_WAIT,          // 602
    // Takes a `Cap<Shm>` in `a0` and mints a `Cap<Lease>` for a ring-3
    // lessor: a member on both counts (2026-09-28, replacing the raw-id 111).
    SYS_IPC_LEASE_GRANT_TYPED,   // 603  mints
    // Takes a `Cap<Port>` in `a0` (wave 11, PORTWAIT): the deadline form of 577.
    SYS_PORT_WAIT_UNTIL_TYPED,   // 604
    // RFC-0055 (wave 11): mints two `Cap<Pipe>` ends into the caller's own
    // table, the `SYS_PORT_CREATE_TYPED` shape. (`SYS_SPAWN_EX`, 608, is not
    // a member: it takes no handle in `a0`, its move list is a different
    // shape, and `tests/host/seccomp-tests` holds it to the shell's profile
    // and, since wave 12, the benchmark's.)
    SYS_PIPE_TYPED,              // 607  mints
    // RFC-0055 S5: a `Cap<Power>` in `a0`; only `POWER.ELF`'s profile lists it.
    SYS_POWER_TYPED,             // 614
    // Wave 12: the other privileged families, each its tool's alone.
    SYS_FLIGHT_TYPED,            // 615  Cap<Motor>
    SYS_BEHAVIOR_TYPED,          // 616  Cap<Power>
    SYS_CONFIG_TYPED,            // 617  Cap<Power>
    SYS_OTA_TYPED,               // 618  Cap<Power>
];

// ---------------------------------------------------------------------------
// Retired numbers.
// ---------------------------------------------------------------------------

/// Syscall numbers that were assigned and are retired. **A retired number is
/// never reused**: dispatch has no arm for it, so a binary that still issues it
/// gets the answer an unassigned number gets, never some other call. A retired
/// number's own name may stay in this file while its callers migrate (marked
/// "Retired (gap 1)"); what the rule forbids is a different call taking the
/// number.
///
///   * 116 — `SYS_CAP_GRANT`, removed 2026-09-03 (see the IPC block above).
///   * RFC-0040 gap 1, by the owner decisions of 2026-09-14, arms deleted in
///     stage 3: the untyped channel family, whose one ring-3 user (a fork
///     mailbox) moves to fast IPC (100-104 and 107, `SYS_IPC_CALL` and
///     `SYS_IPC_REPLY` included, and 506-508); the other untyped object-index
///     calls (105, 106, 115 shared memory; 503-505, 519 io_ring; 511-514
///     ports); the untyped hardware calls with a typed twin (200-202, 210-213,
///     220, 221, 232, 332, 520, 521); the untyped direction call (231 → 576)
///     and angle call (233 → 578); the `HANDLES` table calls (515-517).
///   * The POSIX subset (owner decisions 42 and 43):
///     the signal calls (350-356) and the descriptor copies `SYS_PIPE`,
///     `SYS_DUP`, `SYS_DUP2` (360-362). Their handler functions stay; host
///     tests call them directly.
///   * The untyped file calls with a typed twin (owner decision 96, completed
///     2026-09-19): `SYS_OPEN` (20 → 563) and `SYS_READ` (22 → 564). The
///     decision migrated `libsys`, and the comment above the `Cap<File>` block
///     kept 20 alive for a reason that the same change had already removed —
///     "`abitest` and `brain_client` depend on it" — when both had moved to
///     `sys::open`, which is 563. No profile has granted 20 or 22 since; this
///     makes that fact enforced (`no_profile_grants_a_retired_number`) instead
///     of true by accident, and deletes the two dispatch arms.
///   * `SYS_LSEEK` (24), **a separate decision and not a twin migration**:
///     seek has no typed form, so this removes it from ring 3 rather than
///     replacing it. Nothing called it — no profile granted it and no
///     userspace binary used `libsys::lseek` — and a seek that takes a
///     DESCRIPTOR cannot be reached at all now that `open` returns a handle.
///     It comes back as `SYS_FILE_SEEK_TYPED` when a caller needs it.
///
///     Like the descriptor copies, all three handler functions stay: the host
///     suites (`tests/host/syscall-tests/src/file_ops_seam.rs`, `file_caps.rs`)
///     call `sys_open`/`sys_read`/`sys_lseek` directly, which is how the
///     descriptor seam under `Cap<File>` is still tested from below.
///   * `SYS_IPC_LEASE_GRANT` (111 → 603), owner decision 2026-09-28: the
///     raw region id ring 3 is never told, replaced by the `Cap<Shm>` that
///     names it. The handler function stays (603 reaches it with the id the
///     capability resolves to; `tests/host/syscall-tests/src/lease_calls.rs`
///     calls it directly).
///
///   * `SYS_DRIVER_REQUEST` (525) and `SYS_DRIVER_TRY_REPLY` (526), wave 11
///     (OVSwrap review F3), **retired, not replaced**: neither took a
///     capability or checked ownership, so a task allowed to issue them could
///     queue a request to ANY driver kind (around the `drv_invoke_authorized`
///     check `SYS_DRV_INVOKE` makes) and read ANY reply by its token, a per-kind
///     counter. No profile granted them and no image called them. The handlers
///     are deleted; the in-kernel proxy reaches the queue through
///     `driver_submit_request` directly.
///
/// **The gap-1 names are gone (stage 4).** libsys, userspace and the seccomp
/// profiles no longer name them, so their `pub const`s are removed; only 116
/// keeps a comment above. No `SYS_*` name carries a retired value now
/// (`tests/host/abi-tests` holds `PENDING_NAME_REMOVAL` empty), and no dispatch
/// arm matches one. The literals below keep a `// SYS_*` comment recording
/// the call each number named.
///
/// **Kept:** the descriptor and socket calls (outside gap 1), the fast IPC
/// calls 108-110, the lease calls 112-114, and the other untyped calls that
/// have no typed twin, re-gated on the caller's own capability table. Gap 1's
/// typed forms are 573-578.
pub const RETIRED_SYSCALLS: &[u64] = &[
    20,  // SYS_OPEN   → SYS_FILE_OPEN_TYPED (563)
    22,  // SYS_READ   → SYS_FILE_READ_TYPED (564)
    24,  // SYS_LSEEK  — no typed twin; seek left the POSIX subset
    100, // SYS_IPC_CREATE
    101, // SYS_IPC_SEND
    102, // SYS_IPC_RECEIVE
    103, // SYS_IPC_CALL
    104, // SYS_IPC_REPLY
    105, // SYS_IPC_SHARE
    106, // SYS_IPC_UNSHARE
    107, // SYS_IPC_DESTROY
    111, // SYS_IPC_LEASE_GRANT → SYS_IPC_LEASE_GRANT_TYPED (603)
    115, // SYS_IPC_MAP
    116, // SYS_CAP_GRANT
    200, // SYS_GPIO_READ
    201, // SYS_GPIO_WRITE
    202, // SYS_GPIO_MODE
    210, // SYS_PWM_ENABLE
    211, // SYS_PWM_DISABLE
    212, // SYS_PWM_SET_FREQ
    213, // SYS_PWM_SET_DUTY
    220, // SYS_I2C_READ
    221, // SYS_I2C_WRITE
    231, // SYS_MOTOR_ENABLE
    232, // SYS_MOTOR_SPEED
    233, // SYS_MOTOR_ANGLE
    302, // SYS_DRV_MMAP (RFC-0043: ring 3 maps MMIO only through SYS_MMIO_MAP)
    332, // SYS_SENSOR_READ
    350, // SYS_KILL
    351, // SYS_SIGNAL
    352, // SYS_SIGRETURN
    353, // SYS_SIGPENDING
    354, // SYS_SIGPROCMASK
    355, // SYS_PAUSE
    356, // SYS_ALARM
    360, // SYS_PIPE
    361, // SYS_DUP
    362, // SYS_DUP2
    503, // SYS_IO_SETUP
    504, // SYS_IO_SUBMIT
    505, // SYS_IO_WAIT
    506, // SYS_CHAN_CREATE
    507, // SYS_CHAN_WRITE
    508, // SYS_CHAN_READ
    511, // SYS_PORT_CREATE
    512, // SYS_PORT_BIND
    513, // SYS_PORT_WAIT
    514, // SYS_PORT_UNBIND
    515, // SYS_HANDLE_GRANT
    516, // SYS_HANDLE_REVOKE
    517, // SYS_HANDLE_DUP
    519, // SYS_IO_SUBMIT_ASYNC
    520, // SYS_DRIVER_REGISTER
    521, // SYS_DRIVER_UNREGISTER
    525, // SYS_DRIVER_REQUEST   — no capability, no ownership (wave 11, OVSwrap F3)
    526, // SYS_DRIVER_TRY_REPLY — any reply by a guessable token (wave 11, OVSwrap F3)
];

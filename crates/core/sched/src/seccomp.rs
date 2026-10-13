// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Syscall filter profiles (AQ11): whitelists per task role, and one per
//! shipped ring-3 binary.
//!
//! Profiles restrict which syscalls a task can use. Once installed — by the
//! task itself (`DOMAIN_SET_FILTER`), or by the kernel at exec from
//! [`IMAGE_PROFILES`] — the filter cannot be removed or replaced (one-way).
//!
//! Role profiles (the `DOMAIN_SET_FILTER` id space):
//!   UNRESTRICTED — all syscalls allowed (kernel tasks, default)
//!   MINIMAL      — `COMMON`: exit, getpid, yield, sleep, and the program
//!                  break and the console write (`SYS_INVOKE` with the `LOG_CONSOLE_WRITE`
//!                  class).
//!
//! There is no role profile for hardware. Every device (gpio, i2c, pwm,
//! motor, sensor ...) is an endpoint op reached through the IPC call every
//! client issues, so a role cannot name it by syscall number. What an image
//! may reach is its [`IMAGE_PROFILES`] row: a syscall bitmap plus the
//! `ifaces` word naming the device interfaces it may call.

use crate::task::SyscallFilter;

// Every syscall number the ABI can assign must be answered from the filter's
// bitmap, not from the list scan that exists for wider numbers: otherwise a
// syscall added past the bitmap would still be filtered correctly but would
// quietly pay the scan the bitmap removed. `filter.rs` cannot name
// `azos_abi` (it is dependency-free for the host test crates), so the
// bound is checked here, where the ABI is already in scope.
const _: () = assert!(
    azos_abi::syscall_nr::SYS_NR_RESERVED_UPPER
        < crate::filter::SYSCALL_FILTER_BITMAP_BITS as u64,
    "the ABI's syscall range outgrew the seccomp bitmap: raise SYSCALL_FILTER_BITMAP_BITS",
);

// `filter.rs` cannot name `azos_abi` either: the kinds an op can name are
// checked against its `ops` array here.
const _: () = assert!(
    crate::filter::FILTER_OP_KINDS == azos_abi::invoke::OP_KINDS,
    "the filter's per-kind op classes must hold every kind an op can name",
);

// Syscall numbers for building profiles, DERIVED rather than restated.
//
// These were 29 private literals with a comment saying they "must match
// azos_syscall::numbers exactly" and nothing making them. The reason they
// were literals is real — `azos_syscall` depends on `azos_sched`, so
// this crate importing it would close a cycle — but `azos_abi` has no
// dependencies at all, so the number can come from the same place the kernel
// and ring 3 now get it from (`crates/core/syscall/src/numbers.rs` and
// `crates/core/libsys` both re-export it as of 2026-09-06).
//
// The failure this removes: renumber a syscall on one side and the profile
// silently whitelists a DIFFERENT call — a seccomp filter that permits what it
// was written to forbid, with nothing red anywhere. `tests/host/seccomp-tests`
// exists to compare the two tables; it now compares a value against itself,
// which is the point. Kept as a tripwire for anyone who reintroduces a
// literal here.
//
// The `as u16` narrowing is safe by construction: the same suite asserts every
// assigned number stays inside the frozen range, which is far below u16::MAX.
const SYS_EXIT: u16 = azos_abi::syscall_nr::SYS_EXIT as u16;
const SYS_GETPID: u16 = azos_abi::syscall_nr::SYS_GETPID as u16;
const SYS_YIELD: u16 = azos_abi::syscall_nr::SYS_YIELD as u16;
const SYS_INVOKE: u16 = azos_abi::syscall_nr::SYS_INVOKE as u16;
const SYS_SLEEP_UNTIL: u16 = azos_abi::syscall_nr::SYS_SLEEP_UNTIL as u16;

// Seccomp itself (must be allowed to activate)

/// Profile IDs (the argument of `DOMAIN_SET_FILTER`).
pub const PROFILE_UNRESTRICTED: u64 = 0;
pub const PROFILE_MINIMAL: u64 = 2;

/// Common syscalls allowed in ALL restricted profiles.
const COMMON: &[u16] = &[
    SYS_EXIT, SYS_GETPID, SYS_YIELD, SYS_SLEEP_UNTIL,
    SYS_INVOKE,
];

// WHY A CAP-TYPED ENTRY IS A NARROWER ENTRY.
//
// A cap-typed call takes the resource from a capability resolved against the
// CALLER'S OWN cap table (`cap_store::with_table(tid, ..)`), not from an
// argument the caller chooses, so a task holding no such cap cannot express
// the request at all. Devices went further (D6): they have no syscall number,
// so no profile lists them; the image row's `ifaces` word is the gate.
//
// THE RULE FOR ADDING A TYPED CALL HERE IS ENFORCED, NOT JUST DESCRIBED
// (owner decision, 2026-09-08). The check lives in `tests/host/seccomp-tests`:
//
//   * `TYPED_GRANTS` there is the single table of "this typed call is in a
//     profile, and here is why": `NarrowerTwin(untyped)` for one whose
//     untyped twin is still in the same profile (the socket family), or
//     `OwnerGranted(reason)`.
//   * `every_typed_syscall_in_a_profile_carries_a_written_reason` fails if a
//     member of `azos_abi::syscall_nr::CAP_TYPED_SYSCALLS` appears in a
//     profile below with no row. Adding one here and nowhere else is a red.
//   * `a_narrower_twin_is_only_narrower_if_the_untyped_call_is_there`
//     checks the socket rows: their untyped partner IS present.
//
// The set comes from the ABI rather than a number range because the table is
// ordered by family, not by whether a call takes a capability.
//
// NOT IN ANY ROLE PROFILE: `SYS_CAP_INFO`. It is task-initiated, and
// `activate_profile` below returns `SECCOMP_E_ALREADY` when a filter is
// already enabled — the sandbox is one-way and can never be relaxed to admit
// it later. For a task that sandboxes ITSELF the pattern is: look capability
// handles up FIRST, set the filter (`DOMAIN_SET_FILTER`) AFTER. Putting a
// discovery call in COMMON would widen every role profile, `PROFILE_MINIMAL`
// included, for a call no self-confined task needs to make.
//
// The image profiles at the bottom of this file DO grant it, to exactly the
// binaries that call it. The kernel installs those before the program runs,
// so the look-up-first ordering is not available to them — and the call reads
// only the caller's own capability table (`caps::sys_cap_info` in
// `crates/core/syscall/src/caps.rs`, `cap_store::with_table(tid, ..)`): it
// names what the task already holds and grants nothing.

/// Build a SyscallFilter from a profile ID.
///
/// Returns `None` for an id that names no profile. The `Option` is the
/// whole point: `PROFILE_UNRESTRICTED` legitimately maps to a *disabled*
/// filter, so a bare `SyscallFilter` return value cannot distinguish
/// "the caller asked for no sandbox" from "the caller asked for a
/// sandbox that does not exist". The previous `_ => disabled()` arm
/// collapsed the two, so a typo'd profile id silently produced an
/// unrestricted task while every caller was told it had succeeded.
/// Callers MUST decide explicitly what an unknown id means for them.
pub fn profile_to_filter(profile_id: u64) -> Option<SyscallFilter> {
    Some(match profile_id {
        PROFILE_UNRESTRICTED => SyscallFilter::disabled(),
        PROFILE_MINIMAL => build_filter(&[]),
        _ => return None, // unknown id — NOT "unrestricted"; see the doc above
    })
}

/// Build a filter from common + extra syscalls.
fn build_filter(extra: &[u16]) -> SyscallFilter {
    let mut filter = SyscallFilter::disabled();
    filter.enabled = true;
    for &o in COMMON_OPS {
        filter.allow_op(o);
    }
    for &s in COMMON {
        filter.allow(s);
    }
    for &s in extra {
        filter.allow(s);
    }
    filter
}

/// Error: the task already has a filter installed (one-way, no downgrade).
pub const SECCOMP_E_ALREADY: i64 = -1;
/// Error: `profile_id` names no profile. Nothing was installed.
pub const SECCOMP_E_BADPROFILE: i64 = -2;

/// Activate a security profile on the current task (one-way).
///
/// Returns 0 on success, [`SECCOMP_E_ALREADY`] if a filter is already
/// installed, [`SECCOMP_E_BADPROFILE`] for an unknown profile id.
///
/// The unknown-id check happens BEFORE anything is installed. It used to
/// fall through to a disabled (= unrestricted) filter and still return 0:
/// a task that meant to sandbox itself but passed a typo'd id was told it
/// had succeeded and kept full syscall authority. A security mechanism
/// that reports success while installing nothing is worse than none at
/// all, because the caller stops looking.
///
/// Note for callers: `activate_profile(PROFILE_UNRESTRICTED)` is a
/// deliberate no-op that returns 0 — it installs a disabled filter, so
/// `enabled` stays false and the one-way gate above is NOT burned. That
/// is by design (it names "no sandbox"), but it means a 0 return does not
/// on its own prove the task is now confined.
pub fn activate_profile(profile_id: u64) -> i64 {
    // Reject the unknown id first — never touch the task's filter on a
    // request we could not honour.
    let filter = match profile_to_filter(profile_id) {
        Some(f) => f,
        None => return SECCOMP_E_BADPROFILE,
    };
    let current = crate::scheduler::current_syscall_filter();
    if current.enabled {
        return SECCOMP_E_ALREADY; // already filtered — one-way, can't change
    }
    crate::scheduler::set_current_syscall_filter(filter);
    0
}

// ════════════════════════════════════════════════════════════════════════════
//  IMAGE PROFILES — one per shipped ring-3 binary (owner decision, 2026-09-14)
// ════════════════════════════════════════════════════════════════════════════
//
// Every ring-3 binary the disk image ships runs under a profile of its own:
// exactly the syscalls that binary issues, nothing else. The kernel installs it
// at exec, from `IMAGE_PROFILES`, bound to the SHA-256 of the exact ELF the build
// copies onto the image. No shipped program runs an instruction unconfined,
// none has to cooperate for that to be true, and an image bound to no row does
// not run.
//
// BOUND TO THE BYTES, NOT THE NAME (owner decision 2026-09-14). A row keyed by
// file name followed whatever was copied under that name: another binary copied
// over ABITEST.ELF ran under ABITEST.ELF's row. So each row is bound to the
// SHA-256 of one ELF. `make build/image_hashes.rs` hashes the files the disk-image
// recipe copies (`userspace/image_hashes.py`) and this file `include!`s the result
// (`IMAGE_SHA256`): generated, never written by hand. Every kernel build target
// depends on it, a missing file fails this crate's build, and
// `tests/host/seccomp-tests` fails on a table that no longer matches build/*.elf.
// The exec sites (the autorun loader, the shell's `exec`) hash the bytes they
// read into their own static buffer and hand that same slice to `exec_user`, so
// the bytes checked are the bytes loaded. An image that matches no row is not
// exec'd, and `SAFETY_EXEC_REFUSED` is written durably. `SYS_SPAWN_EX` and the
// Linux `execve` refuse such an image too (`EACCES`, the same record through the
// capability denials' per-task bound): the table is a whitelist of user images
// on every path that starts one. Hashing at compile time
// instead was measured and rejected: const-evaluating SHA-256 over the eleven
// ELFs added 24 s to every compile of this crate.
//
// WHY THE KERNEL INSTALLS IT, AND NOT THE PROGRAM (a `DOMAIN_SET_FILTER` op at
// entry):
//
//   * The filter lives on the task slot, and nothing between exec and the
//     first user instruction resets it. `exec_user` (`process.rs`) never
//     touches `syscall_filter` and keeps the TID and the slot; `sys_fork_impl`
//     copies the parent's filter onto the child. A filter set on the loading
//     task between a successful `exec_user` and `sret_to_user` therefore
//     covers the program from its first instruction, and every child it forks.
//   * A program-installed filter leaves `_start` up to the install call
//     unconfined, and holds only for binaries that make the call and check it.
//     `userspace/tests/abitest` documents that it never calls `seccomp`.
//   * No ABI change: no new profile id, no new libsys constant. The role
//     profiles above remain the only thing DOMAIN_SET_FILTER can ask for.
//
// WHY A SECOND NAMESPACE AND NOT MORE PROFILE IDS. `profile_to_filter` is the
// id space ring 3 passes to DOMAIN_SET_FILTER. Putting per-binary profiles there
// would let any task ask for another binary's profile by number.
//
// ONE TABLE, WRITTEN IN NAMES. Each row lists `SYS_*` constants from
// `azos_abi::syscall_nr`. RFC-0040 gap 1 (one capability authority, the
// untyped twins retired, the ABI break landing before hardware bring-up)
// rewrites this table by renaming and deleting entries, and nothing else.
//
// WHERE EACH SET COMES FROM, AND WHAT KEEPS IT COMPLETE. The binary's source:
// the libsys wrappers it calls, followed transitively, plus the raw `ecall`s it
// writes out. `tests/host/seccomp-tests` (`mod image_profiles`) derives that set
// from the real sources on every run and requires each row to equal it, so a
// binary that starts issuing a new call without a row change fails on the
// host instead of being refused on the board. The rows name, in a comment,
// every place they differ from a plain derivation; the test holds the reasons.
//
// WHAT A CALL OUTSIDE A ROW DOES. The dispatcher (`crates/core/syscall/src/dispatch.rs`,
// `syscall_dispatch_out`) asks `scheduler::current_syscall_verdict`; `invoke`
// asks `scheduler::current_op_verdict` for the op's class. Refused, the task is
// KILLED (owner decision V1.8): `seccomp_deny_kill` / `seccomp_deny_op_kill`
// (`crates/core/syscall/src/handlers.rs`) write
// `trace_event(TRACE_SYSCALL, num, 0xDEAD, ..)` into the trace ring (not
// durable), say so on the console and end the task with exit code 159. In a
// row marked `audit` (CAPTEST.ELF, ABITEST.ELF) the call goes through instead,
// and `SAFETY_SECCOMP_AUDIT` is recorded the way
// the capability denials are: into the ring, through their per-task bound and
// summary with a budget of its own, onto the disk with the watchdog's flush
// (`record_seccomp_audit` in
// `crates/core/syscall/src/handlers.rs`). A number past `u16::MAX` is refused by every
// filter in force, audit or not.
//
// COST. Every syscall of a filtered task pays the check: one bit of the row's
// bitmap (`SyscallFilter::bits`, built by `allow` alongside the list), read on
// the task slot in place, with no copy: the same few instructions whether the
// row lists 2 calls or 60. `LATBENCH.ELF` and `VSBENCH.ELF`
// measure syscall cost, so their numbers include it. Each exec from the autorun
// loader or the shell pays one SHA-256 pass over the image.

/// `SYS_*` names from `azos_abi::syscall_nr`, narrowed to the filter's
/// `u16` the same way as the constants at the top of this file.
macro_rules! sys_nrs {
    ($($name:ident),* $(,)?) => {
        &[$(azos_abi::syscall_nr::$name as u16),*]
    };
}

/// A ring-3 binary the disk image ships, and the only syscalls it may issue.
#[derive(Clone, Copy)]
pub struct ImageProfile {
    /// The name the build copies the binary under (`Makefile`,
    /// `mcopy -i $@ $(..) ::NAME`), which is also its key in `IMAGE_SHA256`.
    /// The row is bound to the SHA-256 of those bytes; the name an exec site
    /// opens is not consulted.
    pub image: &'static str,
    /// Every named syscall the binary issues.
    pub syscalls: &'static [u16],
    /// Allow-and-record (owner decision 2026-09-14): a syscall outside
    /// `syscalls` goes through and is written to the flight recorder as
    /// `SAFETY_SECCOMP_AUDIT`, bounded per task, instead of being refused.
    /// Only the two test binaries whose job is to probe the kernel with calls
    /// it must refuse on its own: their raw probes (`116`, the retired
    /// `SYS_CAP_GRANT`; `999`, unclaimed) reach the dispatcher arm under test,
    /// and nothing they issue outside their row goes unrecorded.
    pub audit: bool,
    /// The kernel-hosted endpoints (`azos_devif::key`) the binary calls: a
    /// device or a kernel service is an endpoint op, so the syscall list says
    /// "may call an endpoint" and this says which. Also the interfaces its
    /// autorun row's grants are kept to (an image's topology grant of an
    /// endpoint it does not list is withheld at seeding).
    pub ifaces: &'static [u16],
    /// The ops of `SYS_INVOKE` the binary issues (`azos_abi::invoke`), listed
    /// by `inv_ops!`. Each op lists its CLASS on its kind: the filter answers
    /// per (kind, class), so a row naming one op of a class grants the class.
    /// A Linux image lists none: the personality performs the op itself.
    pub ops: &'static [u16],
}

/// `SYS_INVOKE` op names for a row: the ops themselves, narrowed.
macro_rules! inv_ops {
    ($($name:ident),* $(,)?) => {
        &[$(azos_abi::invoke::$name),*]
    };
}

/// The ops allowed in every restricted role profile: the console write and the
/// program break.
const COMMON_OPS: &[u16] = inv_ops![LOG_CONSOLE_WRITE, DOMAIN_BRK];

/// No `SYS_INVOKE` op: the row of a binary that issues none.
pub const NO_OPS: &[u16] = &[];
/// The row of a binary whose only `SYS_INVOKE` is its console output.
const CONSOLE_OPS: &[u16] = inv_ops![LOG_CONSOLE_WRITE];

/// No kernel-hosted endpoint: the row of a binary that calls none.
pub const NO_IFACES: &[u16] = &[];

/// One row per ELF the disk image ships, in `Makefile` copy order.
pub const IMAGE_PROFILES: &[ImageProfile] = &[
    // userspace/tests/hello/hello.S: one write, one exit. No image autoruns it; the
    // shell's `exec` does.
    ImageProfile {
        image: "HELLO.ELF",
        syscalls: sys_nrs![SYS_EXIT, SYS_INVOKE, SYS_CAP_INFO],
        audit: false,
        ops: CONSOLE_OPS,
        ifaces: NO_IFACES,
    },
    // userspace/tests/syscall_test/test.S.
    ImageProfile {
        image: "SYSTEST.ELF",
        syscalls: sys_nrs![SYS_EXIT, SYS_GETPID, SYS_INVOKE, SYS_CAP_INFO],
        audit: false,
        ops: CONSOLE_OPS,
        ifaces: NO_IFACES,
    },
    // The ring-3 GPIO driver: looks up its `DriverRegistry` handle (`cap_info`),
    // registers through it (`DOMAIN_DRIVER_REGISTER`) and serves its requests,
    // parked on a timed sleep while none is queued.
    ImageProfile {
        image: "GPIODRV.ELF",
        syscalls: sys_nrs![SYS_EXIT, SYS_SLEEP_UNTIL, SYS_INVOKE, SYS_CAP_INFO],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, DOMAIN_DRIVER_REGISTER],
        ifaces: NO_IFACES,
    },
    // The ring-3 ML service: reads its two model files through `Cap<File>`
    // (`DOMAIN_OPEN`, `NODE_READ`, `SYS_CAP_CLOSE`), looks up its
    // `DriverRegistry` handle and serves the requests of the line it binds.
    // `SYS_YIELD` after a refused reply.
    ImageProfile {
        image: "MLSRV.ELF",
        syscalls: sys_nrs![SYS_EXIT, SYS_YIELD, SYS_INVOKE, SYS_CAP_CLOSE, SYS_CAP_INFO],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, DOMAIN_OPEN, NODE_READ, DOMAIN_DRIVER_REGISTER],
        ifaces: NO_IFACES,
    },
    // Differs from its derivation: it also issues `SYS_IPC_FAST_CALL_EP`,
    // outside this list on purpose, and requires the kill. That is the
    // runtime proof the `userspace: minimal Rust ELF` scenario and abitest's
    // `check_spawn` assert, through the native entries' IPC branch (Chain E
    // cut 7). It was `SYS_GETPID` until that branch existed: the branch is the
    // entry a filter check could be dropped from without any other runtime
    // test noticing.
    ImageProfile {
        image: "UHELLO.ELF",
        syscalls: sys_nrs![SYS_EXIT, SYS_INVOKE, SYS_CAP_INFO],
        audit: false,
        ops: CONSOLE_OPS,
        ifaces: NO_IFACES,
    },
    // RFC-0040 gap 2 stage 2b — the SERVER half of `endpoint.demo`.
    //
    // **Why this is not three more calls in UHELLO.ELF's row above.** A
    // ring-3 program's role on an endpoint is its capability PERMISSION
    // (`READ` serves, `WRITE` calls), and permissions come from the topology
    // row looked up by image name — so one image has one role, and an image
    // that is sometimes a server cannot exist. The first draft of this stage
    // gave `uhello` the serve loop and let it decide at runtime; it hung as
    // autorun, because `SYS_IPC_FAST_ACCEPT` blocks and no client was ever
    // going to wake it. See `userspace/tests/epsrv/src/main.rs`.
    //
    // No `SYS_YIELD` and no handle lookup in a loop: this image accepts
    // exactly once and never polls, and accept is addressed by TID, so it
    // needs no handle. `getpid` stays out of every ring-3 profile that has no
    // use for it.
    ImageProfile {
        image: "EPSRV.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_CAP_INFO,
            SYS_IPC_FAST_ACCEPT, SYS_IPC_FAST_REPLY,
            // RFC-0040 gap 2 stage 4: this image CLOSES the `Cap<Socket>` the
            // client moved to it. That close is the positive proof the
            // capability really crossed — it answers `-ECAPSTALE` for a handle
            // the task does not hold, so it cannot succeed by accident.
            SYS_CAP_CLOSE,
        ],
        audit: false,
        ops: CONSOLE_OPS,
        ifaces: NO_IFACES,
    },
    // The processes `abitest` starts to watch them live, die, be reaped and be
    // orphaned (`userspace/tests/abichild`): one image, the behaviour named by
    // `argv[1]`, so the row is the union of the modes. Its topology row
    // (`ipc-endpoint-canary` builds) holds only the right to start itself, which
    // `SYS_SPAWN_EX` checks: a process tree needs it, and no other native image
    // but the shell and `vsbench` lists the call.
    ImageProfile {
        image: "ABICHILD.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_SLEEP_UNTIL, SYS_YIELD, SYS_GETPID, SYS_CAP_CLOSE,
            SYS_SPAWN_EX, SYS_SERVICE_DISCOVER, SYS_MO_MAP,
            SYS_THREAD_CREATE, SYS_THREAD_EXIT,
            SYS_FOREIGN_ENTRY, SYS_FOREIGN_RESUME,
        ],
        audit: false,
        ops: inv_ops![DOMAIN_BRK, DOMAIN_OPEN, NODE_READ, DOMAIN_SERVICE_REGISTER, DOMAIN_CREATE_PIPE, DOMAIN_SUBREAPER, DOMAIN_SOCKET, NODE_RECVFROM, NODE_SENDTO, DOMAIN_WAIT],
        ifaces: NO_IFACES,
    },
    // RFC-0040 gap 2 stage 4 — the benchmark's server, `endpoint.bench`.
    //
    // Same reasoning as the `EPSRV.ELF` row above, which states it in full:
    // the role is the capability PERMISSION, and the permission comes from
    // the topology row looked up by image name. This image exists at all
    // because `vsbench`'s peer used to be a forked copy of it, and a forked
    // child can never be addressed by capability.
    ImageProfile {
        image: "VSSRV.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_YIELD,
            SYS_IPC_FAST_ACCEPT, SYS_IPC_FAST_REPLY, SYS_IPC_FAST_REPLY_ACCEPT,
            // The ring lanes: map the page whose capability the client moved
            // here, notify/wait on its index words (`DOMAIN_NOTIFY_*`), and
            // report the hart it ran on (`DOMAIN_TASKINFO` reads, through
            // `DOMAIN_STAT`'s class).
            SYS_MO_MAP,
            // The `drv-call` lane (SHMRING). For its span this image is the
            // power-monitor driver (`drv.17` in its topology row): it finds
            // its `DriverRegistry` handle and binds an interrupt line.
            SYS_CAP_INFO,
        ],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, DOMAIN_STAT, DOMAIN_DRIVER_REGISTER, DOMAIN_NOTIFY_WAKE, DOMAIN_NOTIFY_WAIT],
        ifaces: NO_IFACES,
    },
    // Reflex stops a wheel (`speed`, 0) and turns or backs up (`drive`) on the
    // `motor` endpoints, with the register-form call. A row granting a call
    // the binary does not issue is authority a compromised binary gets for
    // free (`no_image_profile_allows_a_call_its_binary_does_not_issue`), and
    // a row missing one it does issue is a crash at the first motor command
    // (seccomp denial KILLS the task, owner V1.8).
    ImageProfile {
        image: "REFLEX.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_SLEEP_UNTIL, SYS_INVOKE, SYS_CAP_INFO,
            SYS_IPC_CALL_V2, SYS_IPC_FAST_CALL_EP,
        ],
        audit: false,
        ops: CONSOLE_OPS,
        ifaces: &[azos_devif::key::MOTOR, azos_devif::key::SENSOR],
    },
    // brain_client: CONFIG.INI through a Cap<File>, the brain link on a
    // Cap<Socket>, sensors, motors, and the ring-3 e-stop (the `motor`
    // endpoints, register form). A forward command is also submitted as one
    // io_ring motor entry (RFC-0041 §E), which the kernel runs only while the
    // row lists the `motor` interface.
    ImageProfile {
        image: "BRAINCLI.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_SLEEP_UNTIL, SYS_INVOKE, SYS_CAP_INFO, SYS_IPC_FAST_CALL_EP,
            SYS_CAP_CLOSE,
            SYS_RING_SETUP, SYS_RING_ENTER,
            // `SYS_IPC_CALL_V2` on two kernel-hosted endpoints: `link_key_init`
            // reads the brain-link PSK from `linkkey` (U06-9), and each
            // RFC-0019 handshake draws the randomness for its ephemeral key and
            // record nonce seed from `entropy` (wave 9, P3/P9). Without it the
            // encrypted link cannot start and the client refuses to run.
            SYS_IPC_CALL_V2,
        ],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, DOMAIN_OPEN, DOMAIN_SOCKET, NODE_READ, NODE_SEND, DOMAIN_STAT],
        ifaces: &[azos_devif::key::ENTROPY, azos_devif::key::LINK_KEY, azos_devif::key::MOTOR, azos_devif::key::SENSOR],
    },
    // AUDIT MODE. captest issues capability calls it expects the kernel to
    // refuse, so every one of them is in the row and reaches the gate under
    // test. Its one call outside the row, number `116` (no longer assigned,
    // issued raw to watch the dispatcher refuse a number that does not
    // answer), goes through and is recorded as SAFETY_SECCOMP_AUDIT.
    ImageProfile {
        image: "CAPTEST.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_MO_UNMAP,
            SYS_IPC_CALL_V2, SYS_IPC_FAST_CALL_EP,
            SYS_CAP_INFO, SYS_CAP_CLOSE,
            // The ring-3 IRQ section, both ISAs since wave 9 (RTC alarm bound
            // to a port, polled with a sleep between tries, then ACKed; then
            // bound to the task itself and waited for), and the vDSO clock the
            // sensor stamps are checked against (SENSORTS).
            SYS_SLEEP_UNTIL,
            // Wave 11 (SHMRING): map a kernel stream's `Cap<Shm>` and sleep
            // on its doorbell word.
            SYS_MO_MAP,
            // The stream fallback: with the ring off, a LiDAR scan is read
            // through the io_ring's `READ_SENSOR` op.
            SYS_RING_SETUP, SYS_RING_ENTER,
            // The ABI cases shared with the micro kernel's captest
            // (`abi_cases.rs`): a fast call through a forged endpoint and a
            // reply to no exchange, both expected to be refused.
            SYS_IPC_FAST_REPLY,
        ],
        audit: true,
        ops: inv_ops![LOG_CONSOLE_WRITE, DOMAIN_CREATE_ENDPOINT, PORT_POLL, DOMAIN_STAT, DOMAIN_OPEN, DOMAIN_MKDIR, NODE_READ, NODE_WRITE, DOMAIN_MMIO_MAP, DEVICE_IRQ_BIND, DOMAIN_NOTIFY_WAIT],
        ifaces: &[
            azos_devif::key::GPIO, azos_devif::key::I2C, azos_devif::key::PWM,
            azos_devif::key::MOTOR, azos_devif::key::SENSOR,
            // RFC-0048 P3: the partition block, issued only where the
            // topology grants `block.part.1` (the `disk-part-row` boot).
            azos_devif::key::BLOCK,
        ],
    },
    ImageProfile {
        image: "LATBENCH.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_GETPID, SYS_INVOKE, SYS_CAP_INFO,
            SYS_IPC_CALL_V2, SYS_IPC_FAST_CALL_EP,
        ],
        audit: false,
        ops: CONSOLE_OPS,
        ifaces: &[azos_devif::key::MOTOR, azos_devif::key::SENSOR],
    },
    // AUDIT MODE. abitest asserts the kernel's answer to wrong and missing
    // arguments, stubs and absent dispatch arms, so each such call is in the
    // row. `999`, unclaimed and issued raw to watch the default arm refuse it,
    // is outside the row, goes through and is recorded. The widest row is below
    // `SYSCALL_FILTER_MAX` (Kconfig).
    //
    // The processes it watches are `ABICHILD.ELF`'s, started with
    // `SYS_SPAWN_EX` (a launch grant on the image in the autorun row, QEMU
    // topologies only), UHELLO.ELF and EPSRV.ELF the same way.
    ImageProfile {
        image: "ABITEST.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_GETPID, SYS_YIELD, SYS_INVOKE, SYS_SLEEP_UNTIL,
            SYS_CAP_INFO, SYS_CAP_CLOSE,
            // `check_service_name_dies_with_its_task`: a child registers a
            // name, exits, and the parent asserts `discover` no longer finds it.
            SYS_SERVICE_DISCOVER,
            // RFC-0040 gap 2 stage 2b: the CALL half only. `abitest` addresses
            // `endpoint.demo` by capability and never by TID, so
            // `SYS_IPC_FAST_CALL_EP` is here and the TID form deliberately is
            // not — a profile that granted both would let the test pass
            // without the capability path ever being exercised.
            SYS_IPC_FAST_CALL_EP,
            // `check_entropy_read` (wave 9, P9): the call on the kernel-hosted
            // `entropy` endpoint.
            SYS_IPC_CALL_V2,
            // `check_threads` and the FP-state checks (wave 13, THREADS).
            SYS_THREAD_CREATE, SYS_THREAD_EXIT, SYS_FUTEX_WAIT, SYS_FUTEX_WAKE,
            // `check_mmap_prot` (wave 13, security).
            SYS_MO_MAP,
        ],
        audit: true,
        ops: inv_ops![LOG_CONSOLE_WRITE, DOMAIN_EXIT_STATS, DOMAIN_SERVICE_REGISTER, DOMAIN_SUBREAPER, PORT_POLL, PORT_BIND, DOMAIN_OPEN, DOMAIN_MKDIR, DOMAIN_SOCKET, NODE_READ, NODE_WRITE, NODE_SEND, DOMAIN_WAIT, DEVICE_IRQ_BIND],
        ifaces: &[azos_devif::key::ENTROPY, azos_devif::key::MOTOR],
    },
    // `SYS_FOREIGN_FORK` is issued as raw asm (`spawn`, the register canary),
    // not through libsys, after the foreign entry that allows it is registered.
    // The mailbox and phase C are typed now: the untyped
    // IPC/shm/port/io_ring/channel calls were retired in RFC-0040 gap 1.
    ImageProfile {
        image: "IPCTEST.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_GETPID, SYS_SLEEP_UNTIL, SYS_INVOKE,
            // RFC-0040 gap 3: phases B and E reach their peer through the
            // fork-inherited capability instead of a raw TID. The endpoint's
            // SERVER creates it (`DOMAIN_CREATE_ENDPOINT`, making itself
            // `owner_tid`) before forking the client, so the client inherits a
            // capability to something its own parent owns; the CLIENT calls
            // through it (`SYS_IPC_FAST_CALL_EP`).
            SYS_IPC_FAST_CALL_EP,
            SYS_IPC_FAST_REPLY, SYS_IPC_FAST_ACCEPT,
            SYS_IPC_FAST_REPLY_ACCEPT,
            SYS_PORT_WAIT,
            SYS_MO_CREATE, SYS_MO_MAP,
            SYS_MO_UNMAP,
            SYS_RING_SETUP, SYS_RING_ENTER, SYS_CAP_CLOSE,
            // Lease IPC from ring 3 (waves 9 and 11, phases L, L2, R and W):
            // `MEMOBJ_LEASE_GRANT` mints the `Cap<Lease>` that
            // `MEMOBJ_LEASE_WAIT` takes; `SYS_CAP_INFO` finds it by lease id;
            // the service calls exchange TIDs with the kernel lessee of
            // `lease-pi3-smoke` (L2). Not ABITEST: its row is the widest.
            SYS_CAP_INFO,
            SYS_SERVICE_DISCOVER,
            // Plan item 7, phase K: force-kill its own children blocked in
            // the waits above.
            SYS_ALERT,
            // D4/L6, phase R: the v2 call is how a `Cap<Shm>` is SHARED (a DUP
            // entry) while the sender keeps its mapping; a MOVE through the v1
            // call (phase H) takes the mapping with it.
            SYS_IPC_CALL_V2, SYS_IPC_ACCEPT_V2, SYS_IPC_REPLY_V2,
            // Its children are copies of it: it registers a foreign entry to be
            // allowed to fork (`SYS_FOREIGN_FORK`).
            SYS_FOREIGN_ENTRY, SYS_FOREIGN_FORK,
        ],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, DOMAIN_EXIT_STATS, DOMAIN_SERVICE_REGISTER, DOMAIN_CREATE_PORT, DOMAIN_CREATE_ENDPOINT, PORT_POLL, PORT_BIND, MEMOBJ_ACQUIRE, MEMOBJ_LEASE_GRANT, MEMOBJ_LEASE_WAIT, DOMAIN_LEASE_ACCEPT, DOMAIN_LEASE_RETURN],
        ifaces: NO_IFACES,
    },
    // The `--features azos` build (the image never carries the Linux one).
    ImageProfile {
        image: "VSBENCH.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_GETPID, SYS_YIELD, SYS_INVOKE,
            // RFC-0040 gap 2 stage 4: the lane addresses its peer
            // (`VSSRV.ELF`, started with `SYS_SPAWN_EX`) by CAPABILITY
            // (`SYS_IPC_FAST_CALL_EP`), which it finds with `SYS_CAP_INFO`. The
            // client never serves, so the accept and reply calls are
            // `VSSRV.ELF`'s.
            SYS_IPC_FAST_CALL_EP, SYS_CAP_INFO,
            SYS_MO_UNMAP,
            // `sensor-read-vdso` maps the task's own page, binds the encoder
            // it holds a `sensor` endpoint for, and reads the same sensor
            // through the v2 call for the comparison.
            SYS_IPC_CALL_V2,
            // The ring lanes: one shm page, its capability MOVED to
            // `VSSRV.ELF` with the setup call, and notify/wait on its index
            // words.
            SYS_MO_CREATE, SYS_MO_MAP,
            // The `ioring-batch` lane: the ring itself, and the op twin of
            // every entry it submits (a ring entry is checked against its
            // twin's row, RFC-0041 §E), so without them every entry would
            // complete refused.
            SYS_RING_SETUP, SYS_RING_ENTER, SYS_CAP_CLOSE,
            SYS_SLEEP_UNTIL,
            // The shell lanes (wave 12): `spawn+wait` (TOOLBOX.ELF as `true`,
            // reaped with `DOMAIN_WAIT`), `pipe-rw` and `pipe+close`.
            SYS_SPAWN_EX,
            // The thread lanes (`thread create+join`, `futex wake+wait rt`).
            SYS_THREAD_CREATE, SYS_THREAD_EXIT, SYS_FUTEX_WAIT, SYS_FUTEX_WAKE,
            // The lanes whose peer is a copy of this process (`pipe-pingpong`,
            // `switch-loaded`, the fork lanes) register a foreign entry to be
            // allowed to fork (`SYS_FOREIGN_FORK`).
            SYS_FOREIGN_ENTRY, SYS_FOREIGN_FORK,
        ],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, DOMAIN_CREATE_PORT, DOMAIN_STAT, DOMAIN_OPEN, DOMAIN_SOCKET, NODE_READ, NODE_WRITE, NODE_SEND, DOMAIN_WAIT, DOMAIN_NOTIFY_WAKE],
        ifaces: &[azos_devif::key::SENSOR],
    },
    // The ring-3 buzzer driver: the v2 accept and reply of the `Buzzer`
    // interface it serves on its endpoint, the register-form calls on its one
    // `pwm` endpoint, and a second thread for the timed steps of a sound
    // (created once, parked on a futex word the main thread bumps).
    ImageProfile {
        image: "BUZZDRV.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_YIELD,
            SYS_CAP_INFO,
            SYS_IPC_ACCEPT_V2, SYS_IPC_REPLY_V2,
            SYS_IPC_FAST_CALL_EP,
            SYS_THREAD_CREATE, SYS_FUTEX_WAIT, SYS_FUTEX_WAKE,
        ],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, DOMAIN_STAT],
        ifaces: &[azos_devif::key::PWM],
    },
    // Wave 9 (DRV1): the ring-3 INA219 driver. The same loop (its park timed
    // to the next sample), and the v2 calls on its one `i2c` endpoint.
    ImageProfile {
        image: "INADRV.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_SLEEP_UNTIL,
            SYS_CAP_INFO,
            SYS_IPC_CALL_V2,
        ],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, DOMAIN_STAT, DOMAIN_DRIVER_REGISTER],
        ifaces: &[azos_devif::key::I2C],
    },
    // RFC-0055 (wave 11): the user shell. The profile that lists
    // `SYS_SPAWN_EX` and `SYS_ALERT` besides the test images that start or
    // stop processes (`tests/host/seccomp-tests` holds the list). Since the
    // Terminal object it does NOT list the console `WAIT` op: console input is
    // the terminal server's (`TERMD.ELF`), and the shell asks it for lines and
    // typed events through `SYS_IPC_CALL_V2` on the `endpoint.term` capability
    // the name server lends it (it asks the name server, through the
    // `endpoint.names` capability its `imports` become, for `term`;
    // `SYS_CAP_INFO` finds that one; `SYS_SLEEP_UNTIL` is the pause while the
    // servers start). No hardware or network call, no way to replace its own
    // image: what it runs is authorised by the CHILD's row. The file ops serve
    // its builtins (`ls`, `cat`, `mkdir`, `rm`) and the redirections it opens
    // and moves to a child; `DOMAIN_WAIT` reaps its jobs.
    ImageProfile {
        image: "SH.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_SLEEP_UNTIL,
            SYS_CAP_CLOSE,
            SYS_CAP_INFO,
            SYS_SPAWN_EX, SYS_ALERT, SYS_IPC_CALL_V2,
        ],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, DOMAIN_CREATE_PIPE, DOMAIN_SUBREAPER, DOMAIN_STAT, DOMAIN_OPEN, DOMAIN_MKDIR, NODE_READ, NODE_WRITE, DOMAIN_WAIT],
        ifaces: NO_IFACES,
    },
    // The Terminal object's server. The ONLY profile that lists the console
    // `WAIT` op (console input) and the v2 accept/reply of the endpoint it
    // serves: no file, spawn, kill or device call. It writes the console only
    // for the prompt and the echo.
    ImageProfile {
        image: "TERMD.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_CAP_INFO, SYS_YIELD,
            SYS_IPC_ACCEPT_V2, SYS_IPC_REPLY_V2,
        ],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, LOG_CONSOLE_WAIT],
        ifaces: NO_IFACES,
    },
    // The Names object's server. Serves `endpoint.names` (accept, reply) and
    // looks up the handles of the endpoints its row lends (`SYS_CAP_INFO`);
    // it reads the signed topology's view through `/proc/names` (open, read,
    // close of a `Cap<File>`, read-only, no grant) and writes the console for
    // its refusal record. No spawn, kill, device, network or console-input
    // call: it lends what its row holds and nothing it is not asked for. The
    // lent capability itself travels in the reply of `SYS_IPC_REPLY_V2`;
    // there is no call that creates authority.
    ImageProfile {
        image: "NAMESD.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_YIELD,
            SYS_IPC_ACCEPT_V2, SYS_IPC_REPLY_V2, SYS_CAP_INFO,
            SYS_CAP_CLOSE,
        ],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, DOMAIN_OPEN, NODE_READ, DOMAIN_STAT],
        ifaces: NO_IFACES,
    },
    // RFC-0055 (wave 11): the shell's multicall tool image. Reads and writes
    // the fds it was moved (`NODE_READ` and `NODE_WRITE` on a `Cap<File>` or a
    // `Cap<Pipe>`, `SYS_CAP_CLOSE`), opens files read-only, lists directories,
    // sleeps.
    ImageProfile {
        image: "TOOLBOX.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_CAP_INFO, SYS_SLEEP_UNTIL,
            SYS_CAP_CLOSE,
        ],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, DOMAIN_STAT, DOMAIN_OPEN, NODE_READ, NODE_WRITE],
        ifaces: NO_IFACES,
    },
    // RFC-0055 S5: the shell's power tool, the first privileged family with a
    // ring-3 form. The ONLY profile whose interfaces list `power`;
    // `SYS_CAP_INFO` finds the endpoint its row grants and `SYS_IPC_CALL_V2`
    // calls it (every refusal is recorded by the op). `NODE_WRITE` is libsys
    // `write` on an fd the shell moved to it (a redirected stdout).
    // `SYS_SLEEP_UNTIL`: the policy server's serve loop waits between
    // evaluations. `SYS_SCHEDCTL`: it says `QOS_BACKGROUND` before that loop
    // (the QoS hint form, which needs no warrant), so its period may slip to
    // share another sleeper's wake-up.
    ImageProfile {
        image: "POWER.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_CAP_INFO, SYS_IPC_CALL_V2,
            SYS_SLEEP_UNTIL, SYS_SCHEDCTL,
        ],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, NODE_WRITE],
        ifaces: &[azos_devif::key::POWER],
    },
    // Wave 12: the other privileged families' tools, the POWER.ELF shape:
    // each the ONLY profile whose interfaces list its family's endpoint,
    // `SYS_CAP_INFO` for the capability its row grants, `SYS_IPC_CALL_V2` to
    // call it, and `NODE_WRITE` for a redirected stdout.
    ImageProfile {
        image: "FLIGHT.ELF",
        syscalls: sys_nrs![SYS_EXIT, SYS_INVOKE, SYS_CAP_INFO, SYS_IPC_CALL_V2],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, NODE_WRITE],
        ifaces: &[azos_devif::key::FLIGHT],
    },
    ImageProfile {
        image: "BEHAVIOR.ELF",
        syscalls: sys_nrs![SYS_EXIT, SYS_INVOKE, SYS_CAP_INFO, SYS_IPC_CALL_V2],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, NODE_WRITE],
        ifaces: &[azos_devif::key::BEHAVIOR],
    },
    ImageProfile {
        image: "CONFIG.ELF",
        syscalls: sys_nrs![SYS_EXIT, SYS_INVOKE, SYS_CAP_INFO, SYS_IPC_CALL_V2],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, NODE_WRITE],
        ifaces: &[azos_devif::key::CONFIG],
    },
    ImageProfile {
        image: "OTA.ELF",
        syscalls: sys_nrs![SYS_EXIT, SYS_INVOKE, SYS_CAP_INFO, SYS_IPC_CALL_V2],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, NODE_WRITE],
        ifaces: &[azos_devif::key::OTA],
    },
    // Wave 15 (TRACE): the tracer's reader, the POWER.ELF shape. The ONLY
    // profile that lists the tracer's ops (`LOG_TRACE_*`); `SYS_CAP_INFO` finds
    // the `Cap<Trace>` its row grants; `SYS_SLEEP_UNTIL` between drains (the
    // rings are polled: the producer rings no doorbell); `DOMAIN_OPEN`,
    // `NODE_WRITE` and `SYS_CAP_CLOSE` for `-o FILE` (and `NODE_WRITE` for a
    // redirected stdout).
    ImageProfile {
        image: "TRACECTL.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_SLEEP_UNTIL, SYS_CAP_INFO,
            SYS_CAP_CLOSE,
        ],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, LOG_TRACE_INFO, LOG_TRACE_MAP, LOG_TRACE_SET_MASK, DOMAIN_OPEN, NODE_WRITE, DOMAIN_STAT],
        ifaces: NO_IFACES,
    },
    // The Decisions object's server. Serves `endpoint.decisions` (the v2
    // accept/reply), reads `/proc/decisions.bin` read-only (open, read, close
    // a typed file), writes its one start-up line to the console. No spawn,
    // no kill, no device, no console input.
    ImageProfile {
        image: "DECISD.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_CAP_INFO, SYS_YIELD,
            SYS_IPC_ACCEPT_V2, SYS_IPC_REPLY_V2,
            SYS_CAP_CLOSE,
        ],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, DOMAIN_OPEN, NODE_READ],
        ifaces: NO_IFACES,
    },
    // The decision query tool: one call into the endpoint its row grants
    // (`SYS_CAP_INFO` finds it), its answer on the console and, for a
    // redirected stdout, `NODE_WRITE`. No file open, no spawn: what it prints
    // is what the server answered. It is a `std` program (the SDK), so its row
    // also carries what the std port layer (`crates/core/stdrt`) can reach
    // whatever the program does: the allocator's mappings and its draw on the
    // entropy pool (`ifaces`), threads and futexes, the clock (`SYS_SLEEP_UNTIL`,
    // `SYS_YIELD`, `DOMAIN_UPTIME` where ring 3 may not read the counter), the
    // console and a redirected stdin (`NODE_READ`; the console itself has no
    // read, console input being the terminal server's alone).
    // `tests/host/seccomp-tests` derives this from the sources (`STDRT`).
    ImageProfile {
        image: "WHY.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_CAP_INFO, SYS_IPC_CALL_V2,
            SYS_MO_MAP, SYS_MO_UNMAP, SYS_GETPID, SYS_SLEEP_UNTIL, SYS_YIELD,
            SYS_FUTEX_WAIT, SYS_FUTEX_WAKE, SYS_THREAD_CREATE, SYS_THREAD_EXIT,
        ],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, NODE_READ, NODE_WRITE, DOMAIN_UPTIME],
        ifaces: &[azos_devif::key::ENTROPY],
    },
    // The package installer. Serves `endpoint.packages` (the v2 accept/reply),
    // copies the package out of the memory object a client hands it (acquire,
    // map, release), reads the volume (open, stat, readdir, read of typed files: the signed
    // topology, the staged packages) and writes only where its tree grant on
    // `/fat/PKG` lets it (a staged package, the journal: open for write,
    // unlink). No spawn, no kill, no device, no socket, no console input.
    ImageProfile {
        image: "PKGD.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_CAP_INFO, SYS_YIELD,
            SYS_IPC_ACCEPT_V2, SYS_IPC_REPLY_V2,
            SYS_CAP_CLOSE, SYS_MO_MAP, SYS_MO_UNMAP,
        ],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, DOMAIN_OPEN, DOMAIN_STAT, DOMAIN_READDIR, DOMAIN_UNLINK, NODE_READ, NODE_WRITE, MEMOBJ_ACQUIRE],
        ifaces: NO_IFACES,
    },
    // The package tool: reads the package file it is told to (stat, open,
    // read) into a new memory object (create, map) that goes to the installer
    // in the call, which releases it; one call into the endpoint its row grants
    // (`SYS_CAP_INFO` finds it), its answer on the console and, for a
    // redirected stdout, `NODE_WRITE`. No spawn, no console input: what it
    // prints is what the installer answered.
    ImageProfile {
        image: "PKG.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_CAP_INFO, SYS_IPC_CALL_V2,
            SYS_CAP_CLOSE, SYS_MO_CREATE, SYS_MO_MAP, SYS_MO_UNMAP,
        ],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, DOMAIN_OPEN, DOMAIN_STAT, NODE_READ, NODE_WRITE],
        ifaces: NO_IFACES,
    },
    // The RPC server (transparent RPC, Phase 9 step 1). Serves the proxy
    // endpoints (accept, reply), calls the endpoints it exports through the
    // warrants it derives for a peer (`SYS_IPC_CALL_V2`, `SYS_CAP_DERIVE`),
    // closes what it minted (`SYS_CAP_CLOSE`: a warrant, a re-minted object),
    // finds its handles (`SYS_CAP_INFO`) and moves MemObj pages across
    // (`SYS_MO_CREATE`, `SYS_MO_MAP`, the acquire op for a size; a region goes
    // back with `SYS_CAP_CLOSE`). `SYS_GETPID`: a boot epoch for its Hellos.
    // Two threads (`SYS_THREAD_CREATE`: the local calls and the link). The link
    // is one UDP socket (create, bind, sendto, recvfrom) at the stack's
    // address; `/proc/rpc` is read (open, read) and the console written for
    // its refusals. No spawn, kill, device or file-write call, and no
    // authority a topology row does not give it: what it may lend is its row's
    // `export`, and the call right on the endpoint behind each.
    ImageProfile {
        image: "RPCSRV.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_YIELD, SYS_SLEEP_UNTIL,
            SYS_IPC_ACCEPT_V2, SYS_IPC_REPLY_V2, SYS_IPC_CALL_V2,
            SYS_CAP_INFO, SYS_CAP_CLOSE, SYS_CAP_DERIVE,
            SYS_MO_CREATE, SYS_MO_MAP, SYS_GETPID,
            SYS_THREAD_CREATE,
        ],
        audit: false,
        ops: inv_ops![
            LOG_CONSOLE_WRITE, DOMAIN_OPEN, NODE_READ,
            DOMAIN_SOCKET, DOMAIN_NET_GETIP, NODE_BIND, NODE_SENDTO, NODE_RECVFROM,
            MEMOBJ_ACQUIRE,
        ],
        ifaces: NO_IFACES,
    },
    // RFC-0053 L0/L0b: the Linux driver server skeleton. Reads its test
    // module off the boot volume (`DOMAIN_OPEN`, `NODE_READ`, `SYS_CAP_CLOSE`),
    // prints through libsys `println`, builds the two regions with anonymous
    // memory (`SYS_MO_MAP`), and is the ONLY profile that lists the module
    // pair (`DOMAIN_MODULE_VERIFY`, `DOMAIN_MODULE_MAP_X`;
    // `tests/host/seccomp-tests` holds it there). Then idles in
    // `SYS_SLEEP_UNTIL`. Its one capability is READ on the entropy pool (the
    // hardened allocator, `azos_ualloc`, keys and randomizes itself from it):
    // `SYS_CAP_INFO` finds the handle in the task's own table,
    // `SYS_IPC_CALL_V2` draws from the kernel-hosted `entropy` interface, and
    // the allocator frees its large allocations with `SYS_MO_UNMAP`. In
    // particular no actuator. The two module ops exist only in a kernel built
    // with `lx-loader`; elsewhere they are -ENOSYS and the row is simply never
    // started (no topology row without `lx-server`).
    ImageProfile {
        image: "LXSRV.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_CAP_INFO, SYS_SLEEP_UNTIL, SYS_MO_MAP, SYS_MO_UNMAP,
            SYS_IPC_CALL_V2,
            SYS_CAP_CLOSE,
        ],
        audit: false,
        ops: inv_ops![LOG_CONSOLE_WRITE, DOMAIN_OPEN, NODE_READ, DOMAIN_STAT, DOMAIN_MODULE_VERIFY],
        ifaces: &[azos_devif::key::ENTROPY],
    },
    // RFC-0047 (wave 12): the Linux personality's test binary, a static
    // Linux ELF (`userspace/tests/lxhello/lxhello.c`). It traps with LINUX
    // numbers; seccomp runs after translation, so this row lists the NATIVE
    // calls its Linux calls reach (`azos_linux_abi::TABLE`), derived from
    // the source by `tests/host/seccomp-tests`. No spawn, no hardware.
    ImageProfile {
        image: "LXHELLO.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_MO_MAP, SYS_MO_UNMAP, SYS_SLEEP_UNTIL,
            SYS_CAP_CLOSE,
            // Stage 3: `clone` in the fork shape (`SYS_FOREIGN_FORK`) and
            // `execve` of itself.
            SYS_FOREIGN_FORK,
            // Wave 13: `kill` of a child (the stop call's ancestry), and
            // `read` of a console lent to it.
            SYS_ALERT,
            // Wave 13: `clone` also reaches the thread create (derived from
            // the personality's table: LXHELLO itself forks only).
            SYS_THREAD_CREATE,
            // Wave 15: `futex` (a robust lock's waiter, a parked thread).
            SYS_FUTEX_WAIT, SYS_FUTEX_WAKE,
            // The ring-3 runtime's own calls (Kconfig LINUX_RUNTIME,
            // `azos_linux_rt::RUNTIME_NATIVE`).
            SYS_FOREIGN_ENTRY, SYS_FOREIGN_RESUME, SYS_GETPID,
        ],
        audit: false,
        ops: NO_OPS,
        ifaces: NO_IFACES,
    },
];

// `IMAGE_SHA256: &[(&str, [u8; 32])]`: the name each shipped ELF is copied
// under on the image, and the SHA-256 of the bytes copied. Generated by
// `userspace/image_hashes.py` from the ELFs the Makefile copies
// (`make build/image_hashes.rs`, a prerequisite of every kernel build target).
// A missing file fails this crate's build, and rustc's error prints the line
// below, comment included; a stale one fails `tests/host/seccomp-tests`, which
// re-hashes build/*.elf against it.
//
// **Two tables, one per ISA, cfg-selected — not one merged table.** This
// crate is compiled separately for each `target_arch`, and `image_for_digest`
// matches by DIGEST (the name is only used afterwards, to look up
// `IMAGE_PROFILES`), so a merged table would have worked functionally: a row
// for `HELLO.ELF`'s riscv64 bytes never matches an aarch64 boot's digest and
// vice versa. It is kept split anyway so `IMAGE_ELFS`/`IMAGE_HASHES` in the
// Makefile — order-checked against the riscv64 disk-image recipe by
// `tests/host/seccomp-tests` — never gains a row that recipe does not itself
// copy; see that Makefile variable's own comment on the invariant.
//
// **Board builds bind their own table** (wave 11 BOARDIMG). The board volume
// carries its own ML service (named key, no `dev-key`), so a kernel built by
// `make vf2`/`k1`/`build-fleet` passes `--features board-image` and binds
// `build/board/image_hashes.rs`, whose MLSRV.ELF row is that service's digest;
// every other kernel binds `build/image_hashes.rs` (the QEMU disks' table). The
// feature predicate sits inside a bare-metal riscv64 module for the reason the
// aarch64 granule predicate does below: host crates that `#[path]`-pull this
// file declare no such feature.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
mod riscv64_image_table {
    #[cfg(not(feature = "board-image"))]
    include!("../../../../build/image_hashes.rs"); // missing? run `make build/image_hashes.rs` in the repo root
    #[cfg(feature = "board-image")]
    include!("../../../../build/board/image_hashes.rs"); // missing? run `make build/board/image_hashes.rs TOPOLOGY_PUBKEY_PATH=<fleet key>`
}
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
use riscv64_image_table::IMAGE_SHA256;
#[cfg(not(all(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64"), target_os = "none")))]
include!("../../../../build/image_hashes.rs"); // host builds: the riscv64 (QEMU) table
// Host builds (`cargo test` on aarch64-apple-darwin, `target_arch =
// "aarch64"` but `target_os != "none"`) fall through to the riscv64 table
// above, NOT an empty one — this crate's seccomp lookups ARE exercised on
// the host: `tests/host/syscall-tests`' `exec_binding` suite (`shims/sched`
// pulls this exact file in by `#[path]`) execs the real `build/uhello.elf`
// (RISC-V bytes) through the real loader and expects its digest to be
// found. An empty table here broke that test — it is not "never
// exercised", the same mistake `process.rs`'s `EXPECTED_MACHINE` host arm
// made for the same reason; see that constant's own comment. This
// preserves the ENTIRE pre-existing host behavior (the `include!` was
// unconditional before this task).
//
// **One aarch64 table per translation granule.** A user image is linked for
// one page size (`-z max-page-size`, `ALIGN(CONSTANT(MAXPAGESIZE))` in its
// `user_aarch64.ld`) and the 16/64 KiB builds come from
// `make AARCH64_PAGE_SIZE=16384|65536`, into their own directory and table.
// The kernel binds the table of the granule it was built for, so an image
// linked for another page size is refused by digest rather than loaded with
// segment boundaries that do not fall on its pages.
//
// The granule selection sits inside a module that only exists on bare-metal
// aarch64, so the host crates that `#[path]`-pull this file (and declare no
// `page-*` features) never evaluate a `feature = "page-16k"` predicate.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
mod aarch64_image_table {
    #[cfg(not(any(feature = "page-16k", feature = "page-64k")))]
    include!("../../../../build/image_hashes_aarch64.rs"); // missing? run `make build/image_hashes_aarch64.rs`
    #[cfg(feature = "page-16k")]
    include!("../../../../build/image_hashes_aarch64_16k.rs"); // missing? run `make AARCH64_PAGE_SIZE=16384 build/image_hashes_aarch64_16k.rs`
    #[cfg(feature = "page-64k")]
    include!("../../../../build/image_hashes_aarch64_64k.rs"); // missing? run `make AARCH64_PAGE_SIZE=65536 build/image_hashes_aarch64_64k.rs`
}
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use aarch64_image_table::IMAGE_SHA256;

// **x86_64: its own table** (`make build/image_hashes_x86_64.rs`, from the
// `build/x86_64/*.elf` the x86_64 disk images carry), for the same reason the
// aarch64 one exists: an x86_64 kernel binds the digests of x86_64 images, so
// an image built for another ISA, or rebuilt after the table, is refused by
// digest. One 4 KiB page size, so one table.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
mod x86_64_image_table {
    include!("../../../../build/image_hashes_x86_64.rs"); // missing? run `make build/image_hashes_x86_64.rs`
}
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use x86_64_image_table::IMAGE_SHA256;

// ── Third-party images (RFC-0047, Kconfig USERSPACE_GPL + BUSYBOX) ──────────
//
// Built only by `make busybox`, from a pinned upstream release, never part of
// the base image and never in `IMAGE_ELFS`: their digests are in a table of
// their own, `build/thirdparty_hashes{,_aarch64}.rs`, which is EMPTY unless
// the program was built (the Makefile writes it with every image-hash table).
// An image is still bound by its digest to its row below; a binary that is
// not the one the build hashed is refused like any other.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
mod riscv64_thirdparty_table {
    include!("../../../../build/thirdparty_hashes.rs"); // missing? run `make build/image_hashes.rs`
}
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
use riscv64_thirdparty_table::THIRDPARTY_SHA256;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
mod aarch64_thirdparty_table {
    // The third-party build is for the 4 KiB granule only.
    #[cfg(not(any(feature = "page-16k", feature = "page-64k")))]
    include!("../../../../build/thirdparty_hashes_aarch64.rs"); // missing? run `make build/image_hashes_aarch64.rs`
    #[cfg(any(feature = "page-16k", feature = "page-64k"))]
    pub const THIRDPARTY_SHA256: &[(&str, [u8; 32])] = &[];
}
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use aarch64_thirdparty_table::THIRDPARTY_SHA256;
// x86_64 builds no third-party image yet: the fallback below, empty.
#[cfg(not(all(any(target_arch = "riscv64", target_arch = "aarch64"), target_os = "none")))]
const THIRDPARTY_SHA256: &[(&str, [u8; 32])] = &[];

/// The rows of the third-party images (RFC-0047). Each lists the NATIVE
/// numbers its Linux calls reach through the personality, as a Linux image's
/// row does (seccomp after translation); `tests/host/seccomp-tests` holds every
/// number to one the personality's table can reach. Without the program built
/// the row binds nothing (its digest table is empty).
pub const THIRDPARTY_PROFILES: &[ImageProfile] = &[
    // BusyBox (`make busybox`, GPL-2.0-only, USERSPACE_GPL): `sh` (ash), the
    // applets it runs in a forked child (`SYS_FOREIGN_FORK`), and `execve` of
    // itself.
    ImageProfile {
        image: "BUSYBOX.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_MO_MAP, SYS_MO_UNMAP, SYS_SLEEP_UNTIL, SYS_YIELD,
            SYS_CAP_CLOSE,
            SYS_FOREIGN_FORK,
            // Wave 13: `kill` (ash's builtin, its children only) and the
            // console the shell lends its foreground job (interactive `sh`).
            SYS_ALERT,
            // The ring-3 runtime's own calls (`azos_linux_rt::RUNTIME_NATIVE`).
            SYS_FOREIGN_ENTRY, SYS_FOREIGN_RESUME, SYS_GETPID,
        ],
        audit: false,
        ops: NO_OPS,
        ifaces: NO_IFACES,
    },
    // Wave 13 (THREADS): `LXTHR.ELF` (`make lxthreads`), our own C linked
    // statically with musl by zig cc, built only beside the third-party
    // images for the same reason (an external toolchain). pthreads: `clone`
    // (thread shape), `futex`, `mmap`/`munmap` for the stacks, a `/tmp` file
    // two threads write.
    ImageProfile {
        image: "LXTHR.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_INVOKE, SYS_MO_MAP, SYS_MO_UNMAP, SYS_YIELD,
            SYS_CAP_CLOSE,
            SYS_THREAD_CREATE, SYS_FUTEX_WAIT, SYS_FUTEX_WAKE,
            // Sleeps between steps (SIGNALS), and a threaded child (fork,
            // wait) ended by a signal (`SYS_FOREIGN_FORK`).
            SYS_SLEEP_UNTIL,
            SYS_FOREIGN_FORK,
            // The ring-3 runtime's own calls (`azos_linux_rt::RUNTIME_NATIVE`).
            SYS_FOREIGN_ENTRY, SYS_FOREIGN_RESUME, SYS_GETPID,
        ],
        audit: false,
        ops: NO_OPS,
        ifaces: NO_IFACES,
    },
];

// The SHA-256 of `crates/core/crypto`, the one implementation the kernel links.
use azos_crypto::sha256;

/// The filter a row describes: its syscalls, each once, and its audit mode.
///
/// Each number is added once because `SyscallFilter::allow` appends without
/// looking and drops past `SYSCALL_FILTER_MAX` in silence; a repeated entry
/// would spend a slot a later call needed.
pub fn image_filter(p: &ImageProfile) -> SyscallFilter {
    let mut filter = SyscallFilter::disabled();
    filter.enabled = true;
    filter.audit = p.audit;
    for &n in p.syscalls {
        if !filter.is_allowed(n) {
            filter.allow(n);
        }
    }
    for &k in p.ifaces {
        filter.allow_iface(k);
    }
    for &o in p.ops {
        filter.allow_op(o);
    }
    filter
}

/// Does the profile list `SYS_FOREIGN_FORK`, the one native call that copies
/// the caller's address space? A Linux image lists it (its `clone` reaches it,
/// in the personality or in the ring-3 runtime), and so do the two test images
/// whose peers are copies of them.
const fn lists_fork(p: &ImageProfile) -> bool {
    let mut i = 0;
    while i < p.syscalls.len() {
        if p.syscalls[i] as u64 == azos_abi::syscall_nr::SYS_FOREIGN_FORK {
            return true;
        }
        i += 1;
    }
    false
}

/// May an image run under a `mem = "locked"` topology row?
///
/// P2 (RFC-0049: a locked task must take no page fault, and a fork puts every
/// page under copy-on-write): its profile does not list `SYS_FOREIGN_FORK`, and
/// it is not in audit mode -- an audit-mode profile lets an unlisted call
/// through, so it cannot promise the absence of anything. The loaders refuse a
/// locked row whose image fails this.
pub fn locked_compatible(p: &ImageProfile) -> bool {
    !p.audit && !lists_fork(p)
}

/// Can an image with this profile fork (RFC-0049 M1, wave 9)? It lists
/// `SYS_FOREIGN_FORK`, or it is in audit mode, which lets an unlisted call
/// through. Memory admission counts a row whose image can fork twice (one COW
/// copy per instance) and a row whose image cannot, once.
pub fn profile_can_fork(p: &ImageProfile) -> bool {
    p.audit || lists_fork(p)
}

/// The image profile named `image` (the name the build copied the bytes
/// under), if the build ships one.
pub fn profile_named(image: &[u8]) -> Option<&'static ImageProfile> {
    IMAGE_PROFILES.iter().chain(THIRDPARTY_PROFILES).find(|p| p.image.as_bytes() == image)
}

/// An incremental SHA-256 over an image read in pieces (RFC-0047 stage 3:
/// images larger than the exec bounce buffer). `finalize` equals
/// [`image_digest`] over the same bytes.
// Host crates that `#[path]`-pull this file never stream an image.
#[allow(unused_imports)]
pub use azos_crypto::sha256::Sha256 as ImageHasher;

/// The SHA-256 of an image, computed by an exec site over the bytes it is about
/// to hand to `exec_user`. One pass over the image, once per exec; never on the
/// syscall path.
pub fn image_digest(elf: &[u8]) -> [u8; 32] {
    sha256::sha256(elf)
}

/// The profile of the shipped image whose bytes have SHA-256 `digest`, or
/// `None` when no shipped ELF has those bytes.
///
/// Found by digest, then by the name the BUILD copied those bytes under
/// (`IMAGE_SHA256`); the name a file is opened under plays no part. A shipped
/// binary copied over another binary's name keeps its own profile. A binary
/// that differs from every shipped one by a single byte has none, and the exec
/// sites refuse to run it (`SAFETY_EXEC_REFUSED`).
pub fn image_for_digest(digest: &[u8; 32]) -> Option<&'static ImageProfile> {
    if let Some((name, _)) = IMAGE_SHA256.iter().find(|(_, d)| d == digest) {
        return IMAGE_PROFILES.iter().find(|p| p.image == *name);
    }
    let (name, _) = THIRDPARTY_SHA256.iter().find(|(_, d)| d == digest)?;
    THIRDPARTY_PROFILES.iter().find(|p| p.image == *name)
}

/// Install `p` on the current task (one-way).
///
/// Called by the kernel's exec sites (the autorun loader, the shell's `exec`)
/// with the row [`image_for_digest`] returned for the bytes they load, after
/// `exec_user` has succeeded and before `sret_to_user`. After, because a failed
/// exec leaves the loader running as a kernel task, and a filter installed for
/// an image that never ran would stay behind for the next one.
///
/// **One-way here**: with a filter already in force this returns
/// [`SECCOMP_E_ALREADY`] and installs nothing. A Linux `execve` does not come
/// here: after it replaces the image it installs the executed image's own
/// filter directly (`azos_syscall::linux`), so the task runs under the row
/// bound to the image it now is, not the one it was. That filter can be wider
/// than the caller's when the caller holds a launch grant for the image.
///
/// Returns 0 when the row's filter is installed.
pub fn install_image_profile(p: &ImageProfile) -> i64 {
    if crate::scheduler::current_syscall_filter().enabled {
        return SECCOMP_E_ALREADY;
    }
    crate::scheduler::set_current_syscall_filter(image_filter(p));
    0
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Syscall filter profiles (AQ11): whitelists per task role, and one per
//! shipped ring-3 binary.
//!
//! Profiles restrict which syscalls a task can use. Once installed — by the
//! task itself via SYS_SECCOMP, or by the kernel at exec from
//! [`IMAGE_PROFILES`] — the filter cannot be removed or replaced (one-way).
//!
//! Role profiles (the SYS_SECCOMP id space):
//!   UNRESTRICTED — all syscalls allowed (kernel tasks, default)
//!   SENSOR       — sensor reads, GPIO input, ADC, and I2C *read and write*.
//!                  No net, no fs, no PWM/motor syscalls.
//!   MOTOR        — PWM, motor control, GPIO output. No net, no fs.
//!   NET          — sockets, DNS. No GPIO, no motors, no sensors.
//!   MINIMAL      — no role-specific syscalls beyond `COMMON`: exit,
//!                  getpid, yield, sleep, write(stdout), putchar, brk,
//!                  and seccomp itself (every restricted profile grants
//!                  `COMMON`, MINIMAL included — it adds nothing on top).
//!
//! After RFC-0040 gap 1 the untyped hardware syscalls are retired, so a
//! restricted profile's hardware access is the cap-typed (`*_TYPED`) calls —
//! the former twins of the retired calls — plus the two untyped survivors that
//! have no typed form (`SYS_ADC_READ`, `SYS_MOTOR_CREATE`). See "WHY THE
//! `*_TYPED` ENTRIES ARE THE ONLY FORM" above `profile_to_filter`.
//!
//! WHAT `SENSOR` NOW GUARANTEES ABOUT I2C (a property the typed migration
//! bought):
//!
//! SENSOR grants `SYS_I2C_WRITE_TYPED`, whose target is a `Cap<I2c>` and NOT a
//! caller-supplied `(bus, addr)` — the capability names the device, packed as
//! `bus << 8 | addr` (`crates/core/ipc/src/i2c_cap.rs`). A SENSOR task can write
//! only the I2C devices it holds a capability for, so it cannot reach an
//! I2C-attached motor controller it was not granted. The retired untyped
//! `SYS_I2C_WRITE(bus, addr, ptr, len)` was bus-wide — its address was an
//! argument seccomp cannot see — and that is precisely the hole the typed form
//! closes. A write is still needed at all because essentially every I2C sensor
//! (MPU-6050, BME280, VL53L0X…) needs register-select and init writes before
//! it can be read.

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
const SYS_SLEEP: u16 = azos_abi::syscall_nr::SYS_SLEEP as u16;
const SYS_WRITE: u16 = azos_abi::syscall_nr::SYS_WRITE as u16;
const SYS_BRK: u16 = azos_abi::syscall_nr::SYS_BRK as u16;
const SYS_PUTCHAR: u16 = azos_abi::syscall_nr::SYS_PUTCHAR as u16;

// Sensor-related (untyped survivors: only ADC, which has no typed form)
const SYS_ADC_READ: u16 = azos_abi::syscall_nr::SYS_ADC_READ as u16;

// Sensor-related, cap-typed twins (RFC-0003 W3+). See "WHY THE `*_TYPED`
// ENTRIES ARE THE ONLY FORM" below.
const SYS_GPIO_READ_TYPED: u16 = azos_abi::syscall_nr::SYS_GPIO_READ_TYPED as u16;
const SYS_I2C_READ_TYPED: u16 = azos_abi::syscall_nr::SYS_I2C_READ_TYPED as u16;
const SYS_I2C_WRITE_TYPED: u16 = azos_abi::syscall_nr::SYS_I2C_WRITE_TYPED as u16;

// Motor-related (untyped survivor: only MOTOR_CREATE, which has no typed form)
const SYS_MOTOR_CREATE: u16 = azos_abi::syscall_nr::SYS_MOTOR_CREATE as u16;

// Motor-related, cap-typed twins (RFC-0003 W3+/W5). See "WHY THE `*_TYPED`
// ENTRIES ARE THE ONLY FORM" below.
const SYS_GPIO_WRITE_TYPED: u16 = azos_abi::syscall_nr::SYS_GPIO_WRITE_TYPED as u16;
const SYS_GPIO_SET_DIR_TYPED: u16 = azos_abi::syscall_nr::SYS_GPIO_SET_DIR_TYPED as u16;
const SYS_PWM_ENABLE_TYPED: u16 = azos_abi::syscall_nr::SYS_PWM_ENABLE_TYPED as u16;
const SYS_PWM_DISABLE_TYPED: u16 = azos_abi::syscall_nr::SYS_PWM_DISABLE_TYPED as u16;
const SYS_PWM_SET_PERIOD_TYPED: u16 = azos_abi::syscall_nr::SYS_PWM_SET_PERIOD_TYPED as u16;
const SYS_PWM_SET_DUTY_TYPED: u16 = azos_abi::syscall_nr::SYS_PWM_SET_DUTY_TYPED as u16;
const SYS_MOTOR_SET_TARGET_TYPED: u16 = azos_abi::syscall_nr::SYS_MOTOR_SET_TARGET_TYPED as u16;
const SYS_MOTOR_ENABLE_TYPED: u16 = azos_abi::syscall_nr::SYS_MOTOR_ENABLE_TYPED as u16;
const SYS_MOTOR_SPEED_TYPED: u16 = azos_abi::syscall_nr::SYS_MOTOR_SPEED_TYPED as u16;
const SYS_MOTOR_DIRECTION_TYPED: u16 = azos_abi::syscall_nr::SYS_MOTOR_DIRECTION_TYPED as u16;
const SYS_SENSOR_READ_TYPED: u16 = azos_abi::syscall_nr::SYS_SENSOR_READ_TYPED as u16;
const SYS_MOTOR_TICK_TYPED: u16 = azos_abi::syscall_nr::SYS_MOTOR_TICK_TYPED as u16;
const SYS_MOTOR_SET_GAINS_TYPED: u16 = azos_abi::syscall_nr::SYS_MOTOR_SET_GAINS_TYPED as u16;
const SYS_MOTOR_RESET_TYPED: u16 = azos_abi::syscall_nr::SYS_MOTOR_RESET_TYPED as u16;

// Network-related
const SYS_SOCKET: u16 = azos_abi::syscall_nr::SYS_SOCKET as u16;
const SYS_BIND: u16 = azos_abi::syscall_nr::SYS_BIND as u16;
const SYS_LISTEN: u16 = azos_abi::syscall_nr::SYS_LISTEN as u16;
const SYS_ACCEPT: u16 = azos_abi::syscall_nr::SYS_ACCEPT as u16;
const SYS_CONNECT: u16 = azos_abi::syscall_nr::SYS_CONNECT as u16;
const SYS_SEND: u16 = azos_abi::syscall_nr::SYS_SEND as u16;
const SYS_RECV: u16 = azos_abi::syscall_nr::SYS_RECV as u16;
const SYS_SOCK_SHUTDOWN: u16 = azos_abi::syscall_nr::SYS_SOCK_SHUTDOWN as u16;
const SYS_SOCKET_TYPED: u16 = azos_abi::syscall_nr::SYS_SOCKET_TYPED as u16;
const SYS_CONNECT_TYPED: u16 = azos_abi::syscall_nr::SYS_CONNECT_TYPED as u16;
const SYS_SEND_TYPED: u16 = azos_abi::syscall_nr::SYS_SEND_TYPED as u16;
const SYS_RECV_TYPED: u16 = azos_abi::syscall_nr::SYS_RECV_TYPED as u16;
const SYS_CLOSE_TYPED: u16 = azos_abi::syscall_nr::SYS_CLOSE_TYPED as u16;
const SYS_MCAST_JOIN_TYPED: u16 = azos_abi::syscall_nr::SYS_MCAST_JOIN_TYPED as u16;
const SYS_MCAST_LEAVE_TYPED: u16 = azos_abi::syscall_nr::SYS_MCAST_LEAVE_TYPED as u16;

// Seccomp itself (must be allowed to activate)
const SYS_SECCOMP: u16 = azos_abi::syscall_nr::SYS_SECCOMP as u16;

/// Profile IDs (passed via SYS_SECCOMP a0 argument).
pub const PROFILE_UNRESTRICTED: u64 = 0;
pub const PROFILE_SENSOR: u64 = 1;
pub const PROFILE_MOTOR: u64 = 2;
pub const PROFILE_NET: u64 = 3;
pub const PROFILE_MINIMAL: u64 = 4;

/// Common syscalls allowed in ALL restricted profiles.
const COMMON: &[u16] = &[
    SYS_EXIT, SYS_GETPID, SYS_YIELD, SYS_SLEEP,
    SYS_WRITE, SYS_PUTCHAR, SYS_BRK, SYS_SECCOMP,
];

// WHY THE `*_TYPED` ENTRIES ARE THE ONLY FORM.
//
// RFC-0040 gap 1 retired the untyped hardware calls, so a profile's hardware
// access is now the cap-typed calls (plus the two untyped survivors with no
// typed form). Each typed call is the FORMER twin of a retired untyped one and
// was always the narrower of the two:
//
//   - The retired call took the resource id as a caller-supplied argument and
//     gated on it. `sys_gpio_write(pin, val)` checked `HandleKind::Gpio(pin)`
//     with `pin` straight out of `a0`. The typed call takes a `Cap<Gpio>` and
//     resolves it against the CALLER'S OWN cap table via
//     `cap_store::with_table(tid, ..)` (`sys_gpio_write_typed`): a task holding
//     no such cap cannot express the request at all.
//   - The clearest case is the driver family. The retired `SYS_DRIVER_REGISTER`
//     took the device kind in `a0`; `SYS_DRIVER_REGISTER_TYPED` has no kind
//     argument and reads it out of the capability
//     (`drvreg_cap::drvreg_kind_of`). Same shape for gpio/pwm/motor.
//   - The motor direction pair narrowed on both axes. The retired
//     `sys_motor_enable(id, dir)` gated on `HandleKind::Motor(id)` — one motor.
//     `SYS_MOTOR_DIRECTION_TYPED` (576) takes the wheel from a `Cap<Motor>`, so
//     the wheel cannot be an argument the caller chooses.
//
// So the profiles grant no more than the retired calls did — less, in fact,
// because the typed forms carry the capability instead of a chooseable id.
//
// THE RULE FOR ADDING A TYPED CALL HERE IS ENFORCED, NOT JUST DESCRIBED
// (owner decision, 2026-09-08). Everything from here down is the reasoning;
// the check that makes it stick lives in `tests/host/seccomp-tests`:
//
//   * `TYPED_GRANTS` there is the single table of "this typed call is in a
//     profile, and here is why" — `FormerTwin(retired)` for a call whose
//     untyped twin RFC-0040 gap 1 retired, `NarrowerTwin(untyped)` for one
//     whose untyped twin is still in the same profile (the socket family), or
//     `OwnerGranted(reason)`. It replaced two hand-kept lists.
//   * `every_typed_syscall_in_a_profile_carries_a_written_reason` fails if a
//     member of `azos_abi::syscall_nr::CAP_TYPED_SYSCALLS` appears in a
//     profile below with no row. Adding one here and nowhere else is a red.
//   * `a_former_twins_untyped_call_is_retired_and_absent` checks each
//     `FormerTwin(n)`: `n` must be in `RETIRED_SYSCALLS` and NOT granted by the
//     profile. `a_narrower_twin_is_only_narrower_if_the_untyped_call_is_there`
//     checks the socket rows the other way — their untyped partner IS present.
//
// The set comes from the ABI rather than a number range because
// `SYS_CAP_LOOKUP` (558), `SYS_WAIT_STATUS` (559) and `SYS_WAITPID` (562) sit
// inside the same block and are not Cap-typed.
//
// TYPED CALLS WITH NO UNTYPED TWIN AT ALL, granted on their own merits, not as
// a former twin: `SYS_I2C_DETECT_TYPED` (544 — its untyped analogue was
// `SYS_I2C_SCAN` 222, which SENSOR does not grant), `SYS_PWM_SET_DUTY_PCT_TYPED`
// (549), the PID family `SYS_MOTOR_TICK_TYPED` (551), `SYS_MOTOR_ENABLED_TYPED`
// (553), `SYS_MOTOR_SET_GAINS_TYPED` (554), `SYS_MOTOR_RESET_TYPED` (555), and
// `SYS_MOTOR_ENABLE_TYPED` (552, arms the PID loop). `SYSCALL_FILTER_MAX` is 128 by default
// and MOTOR sits well under it.
//
// The two untyped survivors: `SYS_ADC_READ` (410) and `SYS_MOTOR_CREATE` (230)
// have no typed form and no retired twin, so they stay untyped in SENSOR and
// MOTOR respectively.
//
// `SYS_PWM_SET_PERIOD_TYPED` (547) is the former twin of the retired
// `SYS_PWM_SET_FREQ` (212) despite the names, because that handler's body
// called `pwm_set_period(ch, period_ns)` — the name said frequency, the code
// set a period.
//
// NOT IN ANY ROLE PROFILE: `SYS_CAP_LOOKUP` (558). It is task-initiated, and
// `activate_profile` below returns `SECCOMP_E_ALREADY` when a filter is
// already enabled — the sandbox is one-way and can never be relaxed to admit
// it later. For a task that sandboxes ITSELF the pattern is: look capability
// handles up FIRST, call SYS_SECCOMP AFTER. Putting a discovery call in COMMON
// would widen every role profile, `PROFILE_MINIMAL` included, for a call no
// self-confined task needs to make.
//
// The image profiles at the bottom of this file DO grant it, to exactly the
// binaries that call it. The kernel installs those before the program runs,
// so the look-up-first ordering is not available to them — and the call reads
// only the caller's own capability table (`sys_cap_lookup` in
// `crates/core/syscall/src/handlers.rs`, `cap_store::with_table(tid, ..)`): it names
// what the task already holds and grants nothing.

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
        PROFILE_SENSOR => build_filter(&[
            // ADC has no typed form and stays untyped; the sensor, GPIO-read
            // and I2C calls are the typed forms only — their untyped twins
            // (332, 200, 220, 221) were retired in RFC-0040 gap 1.
            SYS_ADC_READ,
            SYS_GPIO_READ_TYPED, SYS_I2C_READ_TYPED, SYS_I2C_WRITE_TYPED,
            SYS_SENSOR_READ_TYPED,
        ]),
        PROFILE_MOTOR => build_filter(&[
            // MOTOR_CREATE has no typed form and stays untyped. Everything
            // else is the typed form only: the untyped GPIO-output (201, 202),
            // PWM (210-213), motor-enable/direction (231) and motor-speed
            // (232) calls were retired in RFC-0040 gap 1.
            SYS_MOTOR_CREATE,
            SYS_GPIO_WRITE_TYPED, SYS_GPIO_SET_DIR_TYPED,
            SYS_PWM_ENABLE_TYPED, SYS_PWM_DISABLE_TYPED,
            SYS_PWM_SET_PERIOD_TYPED, SYS_PWM_SET_DUTY_TYPED,
            // SPEED_TYPED (560) is the former twin of the retired 232;
            // DIRECTION_TYPED (576) is the former twin of the retired 231,
            // the direction call reflex and brain_client now reverse through.
            SYS_MOTOR_SPEED_TYPED, SYS_MOTOR_DIRECTION_TYPED,
            // The PID family, granted on their own merits (owner, 2026-09-07):
            // a motor task that cannot arm, aim, tick, tune or reset the PID
            // loop is not a motor task. Each still demands a `Cap<Motor>` with
            // WRITE on BOTH wheels (`crates/core/ipc/src/motor_cap.rs`).
            SYS_MOTOR_ENABLE_TYPED, SYS_MOTOR_SET_TARGET_TYPED,
            SYS_MOTOR_TICK_TYPED, SYS_MOTOR_SET_GAINS_TYPED, SYS_MOTOR_RESET_TYPED,
        ]),
        PROFILE_NET => build_filter(&[
            SYS_SOCKET, SYS_BIND, SYS_LISTEN, SYS_ACCEPT,
            SYS_CONNECT, SYS_SEND, SYS_RECV,
            // Releasing a socket, which this profile could create and never
            // give back: `COMMON` has no close of any kind, so a task under
            // it that reconnected hit `MAX_SOCKETS_PER_TASK` after eight
            // connections and could never open another. No new authority —
            // `sys_sock_close` refuses a socket the caller does not own.
            SYS_SOCK_SHUTDOWN,
            // Cap<Socket> (owner decision 2026-09-13). Connect, send and recv
            // are the narrower twins of the three untyped calls above; creating
            // and closing through a capability are granted on their own
            // merits, with the reasons written in `tests/host/seccomp-tests`
            // (`TYPED_GRANTS`).
            SYS_SOCKET_TYPED, SYS_CONNECT_TYPED, SYS_SEND_TYPED, SYS_RECV_TYPED,
            SYS_CLOSE_TYPED,
            // Multicast on a Cap<Socket> (owner decision 2026-09-13). No untyped
            // twin exists, so both are owner grants; the leave travels with the
            // join so a task here can give a membership back without closing
            // the socket.
            SYS_MCAST_JOIN_TYPED, SYS_MCAST_LEAVE_TYPED,
        ]),
        PROFILE_MINIMAL => build_filter(&[]),
        _ => return None, // unknown id — NOT "unrestricted"; see the doc above
    })
}

/// Build a filter from common + extra syscalls.
fn build_filter(extra: &[u16]) -> SyscallFilter {
    let mut filter = SyscallFilter::disabled();
    filter.enabled = true;
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
// exec'd, and `SAFETY_EXEC_REFUSED` is written durably. Ring-3 `SYS_EXEC` and
// `SYS_EXECPATH` refuse such an image too (`EACCES`, the same record through the
// capability denials' per-task bound): the table is a whitelist of user images
// on every exec path. Hashing at compile time
// instead was measured and rejected: const-evaluating SHA-256 over the eleven
// ELFs added 24 s to every compile of this crate.
//
// WHY THE KERNEL INSTALLS IT, AND NOT THE PROGRAM (a SYS_SECCOMP call at entry):
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
//     profiles above remain the only thing SYS_SECCOMP can ask for.
//
// WHY A SECOND NAMESPACE AND NOT MORE PROFILE IDS. `profile_to_filter` is the
// id space ring 3 passes to SYS_SECCOMP. Putting per-binary profiles there
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
// `syscall_dispatch_out`) asks `scheduler::current_syscall_verdict`. Refused, it
// returns `-1` and writes `trace_event(TRACE_SYSCALL, num, 0xDEAD, ..)` into the
// trace ring, readable through SYS_TRACE_DUMP; the task is not killed, and that
// trace entry is not durable. In a row marked `audit` (CAPTEST.ELF, ABITEST.ELF)
// the call goes through instead, and `SAFETY_SECCOMP_AUDIT` is recorded the way
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
}

/// One row per ELF the disk image ships, in `Makefile` copy order.
pub const IMAGE_PROFILES: &[ImageProfile] = &[
    // userspace/tests/hello/hello.S: one write, one exit. No image autoruns it; the
    // shell's `exec` does.
    ImageProfile {
        image: "HELLO.ELF",
        syscalls: sys_nrs![SYS_EXIT, SYS_WRITE],
        audit: false,
    },
    // userspace/tests/syscall_test/test.S.
    ImageProfile {
        image: "SYSTEST.ELF",
        syscalls: sys_nrs![SYS_EXIT, SYS_GETPID, SYS_WRITE, SYS_BRK],
        audit: false,
    },
    // The ring-3 GPIO driver: looks up its Cap<DriverRegistry>, registers
    // through it, then answers each request and fetches the next in one call
    // (RFC-0041 §D), parked while the queue is empty (610, wave 10; it polled
    // with 581 and a yield before). That call's grant covers both halves: the
    // row lists what the binary issues, so it holds neither 523 nor 524.
    // SYS_SLEEP after a refused call.
    ImageProfile {
        image: "GPIODRV.ELF",
        syscalls: sys_nrs![
            SYS_PUTCHAR, SYS_EXIT, SYS_SLEEP, SYS_WRITE,
            SYS_DRIVER_REPLY_WAIT,
            SYS_DRIVER_REGISTER_TYPED, SYS_CAP_LOOKUP,
        ],
        audit: false,
    },
    // The ring-3 ML service: reads its two model files through Cap<File>,
    // registers as DRV_KIND_ML through its Cap<DriverRegistry>, then serves
    // with SYS_DRIVER_REPLY_WAIT, blocked while no request is queued (as
    // every ring-3 driver does since wave 10; no SYS_DRIVER_REPLY_FETCH). SYS_YIELD after a
    // refused reply, SYS_SLEEP for the kernel-only OP_STALL.
    ImageProfile {
        image: "MLSRV.ELF",
        syscalls: sys_nrs![
            SYS_PUTCHAR, SYS_EXIT, SYS_YIELD, SYS_WRITE, SYS_SLEEP,
            SYS_FILE_OPEN_TYPED, SYS_FILE_READ_TYPED, SYS_CLOSE_TYPED,
            SYS_DRIVER_REPLY_WAIT,
            SYS_DRIVER_REGISTER_TYPED, SYS_CAP_LOOKUP,
        ],
        audit: false,
    },
    // Differs from its derivation: it also issues SYS_GETPID, outside this
    // list on purpose, and requires the refusal. That is the runtime proof
    // the `userspace: minimal Rust ELF` scenario asserts.
    ImageProfile {
        image: "UHELLO.ELF",
        syscalls: sys_nrs![SYS_PUTCHAR, SYS_EXIT, SYS_WRITE],
        audit: false,
    },
    // RFC-0040 gap 2 stage 2b — the SERVER half of `endpoint.demo`.
    //
    // **Why this is not three more syscalls in UHELLO.ELF's row above.** A
    // ring-3 program's role on an endpoint is its capability PERMISSION
    // (`READ` serves, `WRITE` calls), and permissions come from the topology
    // row looked up by image name — so one image has one role, and an image
    // that is sometimes a server cannot exist. The first draft of this stage
    // gave `uhello` the serve loop and let it decide at runtime; it hung as
    // autorun, because `SYS_IPC_FAST_ACCEPT` blocks and no client was ever
    // going to wake it. See `userspace/tests/epsrv/src/main.rs`.
    //
    // No `SYS_YIELD` and no `SYS_CAP_LOOKUP`: this image accepts exactly once
    // and never polls, and accept is addressed by TID, so it needs no handle.
    // `getpid` stays out of every ring-3 profile that has no use for it.
    ImageProfile {
        image: "EPSRV.ELF",
        syscalls: sys_nrs![
            SYS_PUTCHAR, SYS_EXIT, SYS_WRITE,
            SYS_IPC_FAST_ACCEPT, SYS_IPC_FAST_REPLY,
            // RFC-0040 gap 2 stage 4: this image CLOSES the `Cap<Socket>` the
            // client moved to it. That close is the positive proof the
            // capability really crossed — it answers `-ECAPSTALE` for a handle
            // the task does not hold, so it cannot succeed by accident.
            SYS_CLOSE_TYPED,
        ],
        audit: false,
    },
    // RFC-0040 gap 2 stage 4 — the benchmark's server, `endpoint.bench`.
    //
    // Same reasoning as the `EPSRV.ELF` row below, which states it in full:
    // the role is the capability PERMISSION, and the permission comes from
    // the topology row looked up by image name. This image exists at all
    // because `vsbench`'s peer used to be a `fork()`ed child, and a forked
    // child can never be addressed by capability.
    ImageProfile {
        image: "VSSRV.ELF",
        syscalls: sys_nrs![
            SYS_PUTCHAR, SYS_EXIT, SYS_WRITE, SYS_YIELD,
            SYS_IPC_FAST_ACCEPT, SYS_IPC_FAST_REPLY, SYS_IPC_FAST_REPLY_ACCEPT,
            // Wave 6 ring lanes: map the page whose capability the client
            // moved here, notify/wait on its index words, and report the
            // hart it ran on (`SYS_TASKINFO` slot 4).
            SYS_SHM_MAP_TYPED, SYS_NOTIFY_WAIT, SYS_NOTIFY_WAKE, SYS_TASKINFO,
            // Wave 11 (SHMRING): the `drv-call` lane. For its span this image
            // is the power-monitor driver (`drv.17` in its topology row):
            // register, serve from 610, publish the last reply alone (524).
            SYS_CAP_LOOKUP, SYS_DRIVER_REGISTER_TYPED, SYS_DRIVER_REPLY_WAIT,
            SYS_DRIVER_REPLY,
        ],
        audit: false,
    },
    // Reflex stops through SYS_MOTOR_SPEED_TYPED (560, speed=0) and turns/
    // backs up through SYS_MOTOR_MOVE_TYPED (584, U11-12: direction AND
    // speed in one call). It no longer calls SYS_MOTOR_DIRECTION_TYPED
    // (576) at all — `motor_move_typed` replaced that call in
    // `userspace/services/reflex/src/main.rs` the same day 584 was wired in, so 576
    // is removed here too: a row granting a call the binary does not issue
    // is authority a compromised binary gets for free
    // (`no_image_profile_allows_a_call_its_binary_does_not_issue`).
    // 584 itself is why this row changed at all: seccomp denial now KILLS
    // the task (owner V1.8), so a row missing a call an image actually
    // makes is not a narrower profile, it's a crash at the first motor
    // command in every gate row.
    ImageProfile {
        image: "REFLEX.ELF",
        syscalls: sys_nrs![
            SYS_PUTCHAR, SYS_EXIT, SYS_SLEEP, SYS_WRITE, SYS_CAP_LOOKUP,
            SYS_MOTOR_SPEED_TYPED, SYS_MOTOR_MOVE_TYPED, SYS_SENSOR_READ_TYPED,
        ],
        audit: false,
    },
    // brain_client: CONFIG.INI through a Cap<File>, the brain link on a
    // Cap<Socket>, sensors, motors, and the ring-3 e-stop. A forward command
    // is also submitted as one io_ring motor entry (RFC-0041 §E), which the
    // kernel runs only while SYS_MOTOR_SPEED_TYPED is in this row.
    ImageProfile {
        image: "BRAINCLI.ELF",
        syscalls: sys_nrs![
            SYS_PUTCHAR, SYS_EXIT, SYS_SLEEP,
            SYS_FILE_OPEN_TYPED, SYS_FILE_READ_TYPED, SYS_WRITE,
            SYS_UPTIME, SYS_ROBOT_ESTOP,
            SYS_CAP_LOOKUP, SYS_MOTOR_SPEED_TYPED, SYS_MOTOR_DIRECTION_TYPED,
            SYS_SENSOR_READ_TYPED,
            SYS_CLOSE_TYPED, SYS_SOCKET_TYPED, SYS_CONNECT_TYPED,
            SYS_SEND_TYPED, SYS_RECV_TYPED,
            SYS_IORING_CREATE_TYPED, SYS_IORING_SUBMIT_TYPED,
            // U06-9 (2026-09-26): `link_key_init` now reads the brain-link
            // PSK through this call instead of opening `/fat/LINK.KEY` — the
            // FAT copy is gone from `disk-braincli-linkkey.img`, so without
            // this the row's own autorun binary is KILLED (exit 159) at the
            // first thing it does after the motor/sensor capability checks.
            SYS_LINK_KEY_READ_TYPED,
            // Wave 9 (P3/P9): fresh randomness for each RFC-0019 handshake's
            // ephemeral key and record nonce seed. Without it the encrypted
            // link cannot start and the client refuses to run.
            SYS_ENTROPY_READ_TYPED,
        ],
        audit: false,
    },
    // AUDIT MODE. captest issues capability calls it expects the kernel to
    // refuse, so every one of them is in the row and reaches the gate under
    // test. Its one call outside the row, `116` (the retired SYS_CAP_GRANT,
    // issued raw to watch the dispatcher refuse a number that no longer
    // answers), goes through and is recorded as SAFETY_SECCOMP_AUDIT.
    ImageProfile {
        image: "CAPTEST.ELF",
        syscalls: sys_nrs![
            SYS_PUTCHAR, SYS_EXIT, SYS_CLOSE, SYS_WRITE,
            SYS_ADC_READ, SYS_SENSOR_READ_TYPED, SYS_MOTOR_SPEED_TYPED,
            SYS_MMAP, SYS_MUNMAP,
            SYS_GPIO_READ_TYPED, SYS_GPIO_WRITE_TYPED, SYS_GPIO_SET_DIR_TYPED,
            SYS_I2C_READ_TYPED, SYS_I2C_DETECT_TYPED,
            SYS_PWM_ENABLE_TYPED, SYS_PWM_DISABLE_TYPED,
            SYS_PWM_SET_PERIOD_TYPED, SYS_PWM_SET_DUTY_PCT_TYPED,
            SYS_MOTOR_SET_TARGET_TYPED, SYS_MOTOR_TICK_TYPED,
            SYS_MOTOR_ENABLE_TYPED, SYS_MOTOR_ENABLED_TYPED,
            SYS_MOTOR_SET_GAINS_TYPED, SYS_MOTOR_RESET_TYPED,
            SYS_CAP_LOOKUP,
            SYS_FILE_OPEN_TYPED, SYS_FILE_READ_TYPED, SYS_FILE_WRITE_TYPED,
            SYS_CLOSE_TYPED,
            SYS_MMIO_MAP,
            // The ring-3 IRQ section, both ISAs since wave 9 (RTC alarm bound
            // to a port, polled with a sleep between tries, then ACKed; then
            // bound to the task itself and waited for).
            SYS_SLEEP, SYS_PORT_CREATE_TYPED, SYS_PORT_POLL_TYPED,
            SYS_PORT_BIND_TYPED, SYS_DRV_IRQ_ACK,
            // Owner round 23 (wave 9): the five new file calls, and the ramfs
            // directory the positive rmdir removes. Here and not in ABITEST's
            // row, which is one short of `SYSCALL_FILTER_MAX`.
            SYS_STATFS, SYS_FSYNC_TYPED, SYS_TRUNCATE, SYS_RENAME, SYS_RMDIR,
            SYS_MKDIR,
            // RFC-0048 P3: the partition block, issued only where the
            // topology grants `disk.part.1` (the `disk-part-row` boot).
            SYS_DISK_READ, SYS_DISK_WRITE,
            // Wave 10: a refused unlink outside every granted tree, and
            // SYS_DISK_SIZE per partition in the partition block.
            SYS_UNLINK, SYS_DISK_SIZE,

            SYS_IRQ_BIND, SYS_DRV_IRQ_WAIT,
            // Wave 11 (SENSORTS): the stamped read of each granted sensor,
            // checked against the vDSO clock — whose riscv64 reader falls
            // back to SYS_UPTIME where `rdtime` is not native.
            SYS_SENSOR_READ_TS, SYS_UPTIME,
            // Wave 11 (SHMRING): map a kernel stream's `Cap<Shm>` and sleep
            // on its doorbell word.
            SYS_SHM_MAP_TYPED, SYS_NOTIFY_WAIT,
        ],
        audit: true,
    },
    ImageProfile {
        image: "LATBENCH.ELF",
        syscalls: sys_nrs![
            SYS_PUTCHAR, SYS_EXIT, SYS_GETPID, SYS_WRITE, SYS_CAP_LOOKUP,
            SYS_SENSOR_READ_TYPED, SYS_MOTOR_SPEED_TYPED, SYS_ADC_READ,
        ],
        audit: false,
    },
    // AUDIT MODE. abitest asserts the kernel's answer to wrong and missing
    // arguments, stubs and absent dispatch arms, so each such call is in the
    // row. `999`, unclaimed and issued raw to watch the default arm refuse it,
    // is outside the row, goes through and is recorded. The widest row, 74 of
    // `SYSCALL_FILTER_MAX` (Kconfig, default 128 since wave 15; 96 since wave 9, 64 before).
    //
    // Differs from its derivation: SYS_MKDIR, SYS_DISK_READ and
    // SYS_DISK_WRITE appear in its source and are never
    // issued — every call site hands the wrapper an argument it refuses before
    // the ecall, and the check requires exactly that refusal.
    ImageProfile {
        image: "ABITEST.ELF",
        syscalls: sys_nrs![
            SYS_GETCHAR, SYS_EXIT, SYS_GETPID, SYS_YIELD,
            SYS_FORK, SYS_EXEC, SYS_WAIT, SYS_SLEEP, SYS_EXECPATH,
            SYS_WRITE, SYS_SLEEP_UNTIL,
            // The exec test parks the leader in a port wait (bind a timer, wait).
            SYS_PORT_BIND_TYPED, SYS_PORT_WAIT_TYPED,
            SYS_MEMINFO, SYS_TASKINFO, SYS_UPTIME,
            SYS_STAT, SYS_CHDIR, SYS_GETCWD, SYS_MOUNT, SYS_UMOUNT, SYS_SYNC,
            SYS_NET_GETIP, SYS_DRV_HEARTBEAT,
            SYS_ROBOT_INIT, SYS_ROBOT_ESTOP, SYS_SENSOR_INFO, SYS_PLATFORM_TYPE,
            SYS_SOCKET, SYS_BIND, SYS_CONNECT, SYS_SEND, SYS_RECV,
            SYS_SENDTO, SYS_RECVFROM, SYS_SOCK_SHUTDOWN,
            SYS_BRK, SYS_TRACE_DUMP, SYS_CAP_LOOKUP,
            SYS_WAIT_STATUS, SYS_WAITPID, SYS_SPAWN,
            // `check_orphans` (wave 13): the subreaper half.
            SYS_TASK_SUBREAPER,
            SYS_FILE_OPEN_TYPED, SYS_FILE_READ_TYPED, SYS_FILE_WRITE_TYPED,
            SYS_CLOSE_TYPED, SYS_SOCKET_TYPED, SYS_CONNECT_TYPED,
            SYS_SEND_TYPED, SYS_RECV_TYPED,
            SYS_MCAST_JOIN_TYPED, SYS_MCAST_LEAVE_TYPED,
            // `check_service_name_dies_with_its_task`: a forked child registers
            // a name, exits, and the parent asserts `discover` no longer finds it.
            SYS_SERVICE_REGISTER, SYS_SERVICE_DISCOVER,
            // RFC-0040 gap 2 stage 2b: the CALL half only. `abitest` addresses
            // `endpoint.demo` by capability and never by TID, so 582 is here
            // and 108 (`SYS_IPC_FAST_CALL`, the TID form) deliberately is not
            // — a profile that granted both would let the test pass without
            // the capability path ever being exercised.
            SYS_IPC_FAST_CALL_EP,
            // `check_inline_dispatch_arms_refuse`: the arms written inline in
            // `dispatch.rs`, which no host suite compiles. Each is issued with
            // an argument its arm refuses.
            SYS_IPC_LEASE_RETURN, SYS_IPC_LEASE_FREE, SYS_DNS_RESOLVE,
            SYS_DRV_REGISTER, SYS_DRV_IRQ_ACK, SYS_DRV_DMA_ALLOC, SYS_DRV_DMA_FREE,
            SYS_IRQ_BIND,
            // `check_entropy_read` (wave 9, P9). Listed so the kernel seeds
            // this image a `Cap<Entropy>` (autorun withholds it from a row
            // that does not list the call).
            SYS_ENTROPY_READ_TYPED,
            // `check_exit_storm` (wave 11, EXIT2): the exit-path counters it
            // reads around a fork/exit storm.
            SYS_EXIT_STATS,
            // `check_fork_child_holds_only_its_row` (wave 13, NATFORK): a
            // runtime port the parent creates, probed from its fork child.
            SYS_PORT_CREATE_TYPED, SYS_PORT_POLL_TYPED, SYS_PORT_DESTROY_TYPED,
            // `check_threads` (wave 13, THREADS).
            SYS_THREAD_CREATE, SYS_THREAD_EXIT, SYS_FUTEX_WAIT, SYS_FUTEX_WAKE,
            // `check_mmap_prot` (wave 13, security).
            SYS_MMAP,
        ],
        audit: true,
    },
    // SYS_FORK is issued as raw asm (`spawn`, the register canary), not
    // through libsys. The mailbox and phase C are typed now: the untyped
    // IPC/shm/port/io_ring/channel calls were retired in RFC-0040 gap 1.
    ImageProfile {
        image: "IPCTEST.ELF",
        syscalls: sys_nrs![
            SYS_PUTCHAR, SYS_EXIT, SYS_GETPID, SYS_FORK, SYS_SLEEP, SYS_WRITE,
            SYS_UPTIME,
            // **`SYS_IPC_FAST_CALL` (108) is granted HERE and nowhere else**,
            // and only under `qemu` — the dispatcher does not compile the arm
            // into a board build at all (`crates/core/syscall/src/dispatch.rs`).
            //
            // This image addresses its peers by raw TID because they are
            // `fork()`ed children: a forked child holds nothing of its parent's
            // runtime objects (only its descriptors and its row's
            // capabilities), so there is no handle to call with. Reaching them by capability
            // needs a bootstrap grant at fork, which is RFC-0040 gap 3. Until
            // then the TID form stays, contained to a test image that no board
            // runs.
            //
            // Phase A, the mailbox and the heartbeat still address the parent
            // this way — 108 stays granted for them.
            SYS_IPC_FAST_CALL,
            // RFC-0040 gap 3 lands: phases B and E now reach their peer
            // through the fork-inherited capability instead of a raw TID, so
            // both halves of the primitive that closes gap 3 are granted:
            //
            //  * `SYS_ENDPOINT_CREATE_TYPED` (583) — the endpoint's SERVER
            //    creates it (making itself `owner_tid`) before forking the
            //    client, so the client inherits a capability to something
            //    its own parent owns. This is the ONLY primitive that mints
            //    an endpoint; "deliberately callerless" until this change.
            //  * `SYS_IPC_FAST_CALL_EP` (582) — the CLIENT calls through the
            //    inherited capability rather than a guessed TID.
            SYS_ENDPOINT_CREATE_TYPED,
            SYS_IPC_FAST_CALL_EP,
            SYS_IPC_FAST_REPLY, SYS_IPC_FAST_ACCEPT,
            SYS_IPC_FAST_REPLY_ACCEPT,
            SYS_CHAN_CREATE_TYPED, SYS_CHAN_WRITE_TYPED, SYS_CHAN_READ_TYPED,
            SYS_PORT_CREATE_TYPED, SYS_PORT_POLL_TYPED, SYS_PORT_BIND_TYPED,
            SYS_PORT_DESTROY_TYPED, SYS_PORT_WAIT_TYPED,
            // Wave 11, phase P: the multi-source wait with a deadline.
            SYS_PORT_WAIT_UNTIL_TYPED,
            SYS_SHM_CREATE_TYPED, SYS_SHM_MAP_TYPED, SYS_SHM_ACQUIRE_TYPED,
            SYS_SHM_RELEASE_TYPED,
            SYS_IORING_CREATE_TYPED, SYS_IORING_SUBMIT_TYPED, SYS_IORING_DESTROY_TYPED,
            SYS_CLOSE_TYPED,
            // Wave 9, phases L and L2: lease IPC from ring 3. GRANT (603,
            // typed since 2026-09-28: it takes the `Cap<Shm>`) mints the
            // `Cap<Lease>` that WAIT (602) takes; CAP_LOOKUP finds it by lease
            // id; the service calls exchange TIDs with the kernel lessee of
            // `lease-pi3-smoke` (L2). Not ABITEST: its row is the widest (72 of 96).
            SYS_IPC_LEASE_GRANT_TYPED, SYS_IPC_LEASE_ACCEPT, SYS_IPC_LEASE_RETURN,
            SYS_IPC_LEASE_FREE, SYS_IPC_LEASE_WAIT, SYS_CAP_LOOKUP,
            SYS_SERVICE_REGISTER, SYS_SERVICE_DISCOVER,
            // Wave 11 (LEASE2), phases R and W: robust notify words (the
            // takeover's unlock wakes), the exit status of a lessee or holder
            // the kernel killed, and the revoked-lease fault counter
            // (`EXIT_STAT_LEASE_REVOKED_FAULTS`).
            SYS_NOTIFY_WAIT, SYS_NOTIFY_WAKE, SYS_WAITPID, SYS_EXIT_STATS,
            // Wave 11 (LEASE3): the robust register/drop and accept-and-map,
            // numbers of their own since they left 592's and 112's argument
            // space. Only this image calls them.
            SYS_NOTIFY_ROBUST, SYS_IPC_LEASE_ACCEPT_MAP,
            // Plan item 7, phase K: force-kill its own children blocked in
            // the waits above (not ABITEST: its row is the widest).
            SYS_TASK_KILL,
        ],
        audit: false,
    },
    // The `--features azos` build (the image never carries the Linux one).
    ImageProfile {
        image: "VSBENCH.ELF",
        syscalls: sys_nrs![
            // Wave 14: no `SYS_WAIT` -- `fork+exit` reaps its own child with
            // `SYS_WAITPID` (below) and nothing else polls for any child.
            SYS_EXIT, SYS_GETPID, SYS_YIELD, SYS_FORK, SYS_WRITE,
            // RFC-0040 gap 2 stage 4. Three changes, all consequences of the
            // peer becoming an exec'd image:
            //
            //  * 108 → 582: the lane addresses its peer by CAPABILITY, and a
            //    TID is no longer something this binary knows.
            //  * `SYS_IPC_FAST_REPLY` (109), `_ACCEPT` (110) and
            //    `_REPLY_ACCEPT` (580) are GONE. The client never serves, so
            //    the loop moved to `VSSRV.ELF` and this row stopped granting
            //    the three calls that only a server makes.
            //  * `SYS_SPAWN` and `SYS_CAP_LOOKUP` arrive: it starts its peer
            //    and finds the endpoint the peer serves.
            SYS_IPC_FAST_CALL_EP, SYS_SPAWN, SYS_CAP_LOOKUP,
            // `serve()` is unreachable on this ABI but still compiled, and it
            // reports the bug before exiting.
            SYS_PUTCHAR,
            SYS_TASKINFO, SYS_UPTIME, SYS_NET_GETIP,
            SYS_SOCKET, SYS_BIND, SYS_CONNECT, SYS_SEND, SYS_RECV,
            SYS_BRK, SYS_MMAP, SYS_MUNMAP, SYS_WAITPID,
            // Wave 6 (front V), appended LAST: the filter is a linear scan
            // per syscall and `syscall-floor` (GETPID, first) must not move.
            // `sensor-read-vdso` maps the task's own page, binds the encoder
            // it holds a `Cap<Sensor>` for, and reads the same sensor through
            // 561 for the comparison.
            SYS_VDSO_TASK_MAP, SYS_VDSO_SENSOR_BIND, SYS_SENSOR_READ_TYPED,
            // The ring lanes: one shm page, its capability MOVED to
            // `VSSRV.ELF` with the setup call (582's `a5`), and notify/wait on
            // its index words.
            SYS_SHM_CREATE_TYPED, SYS_SHM_MAP_TYPED, SYS_NOTIFY_WAIT, SYS_NOTIFY_WAKE,
            // The `ioring-batch` lane: the ring itself, and the typed
            // twin of every entry it submits — a ring entry is checked against
            // its twin's row (RFC-0041 §E), so without them every entry would
            // complete refused. Appended, so no call measured above moves in
            // the row's linear scan.
            SYS_IORING_CREATE_TYPED, SYS_IORING_SUBMIT_TYPED, SYS_IORING_DESTROY_TYPED,
            SYS_CHAN_CREATE_TYPED, SYS_CHAN_WRITE_TYPED, SYS_CHAN_READ_TYPED,
            SYS_SLEEP_UNTIL, SYS_CLOSE_TYPED,
            // The SQPOLL lane's refusal check: a forged `Cap<File>` read,
            // which must be refused by the capability, not by this row.
            SYS_FILE_READ_TYPED,
            // Wave 11 (SENSORTS): the `sensor-read-ts` lane. Appended, so
            // no call measured above moves in the row's linear scan.
            SYS_SENSOR_READ_TS,
            // Round 48: the `file-ord` lane opens its own image (563; 564
            // and 566 are listed above). Appended, as the rest.
            SYS_FILE_OPEN_TYPED,
            // Wave 12: the shell lanes — `spawn+wait` (TOOLBOX.ELF as
            // `true`, reaped with 562 above), `pipe-rw` and `pipe+close`
            // (the pipe's read and close are 564/566 above). Appended.
            SYS_SPAWN_EX, SYS_PIPE_TYPED, SYS_FILE_WRITE_TYPED,
            // Wave 13: the thread lanes (`thread create+join`, `futex wake+wait rt`).
            SYS_THREAD_CREATE, SYS_THREAD_EXIT, SYS_FUTEX_WAIT, SYS_FUTEX_WAKE,
        ],
        audit: false,
    },
    // Wave 9 (DRV1): the ring-3 buzzer driver. gpio_drv's serve loop (610
    // since wave 10, its park timed to the next step of a sound), and the
    // four typed PWM calls behind its one `Cap<Pwm>`.
    ImageProfile {
        image: "BUZZDRV.ELF",
        syscalls: sys_nrs![
            SYS_PUTCHAR, SYS_EXIT, SYS_WRITE, SYS_SLEEP,
            SYS_DRIVER_REPLY_WAIT,
            // The vDSO clock (`vdso_now_ns`) falls back to SYS_UPTIME where
            // `rdtime` is not native.
            SYS_UPTIME,
            SYS_DRIVER_REGISTER_TYPED, SYS_CAP_LOOKUP,
            SYS_PWM_ENABLE_TYPED, SYS_PWM_DISABLE_TYPED,
            SYS_PWM_SET_PERIOD_TYPED, SYS_PWM_SET_DUTY_PCT_TYPED,
        ],
        audit: false,
    },
    // Wave 9 (DRV1): the ring-3 INA219 driver. The same loop (its park timed
    // to the next sample), and the two typed I2C calls behind its one
    // `Cap<I2c>`.
    ImageProfile {
        image: "INADRV.ELF",
        syscalls: sys_nrs![
            SYS_PUTCHAR, SYS_EXIT, SYS_WRITE, SYS_SLEEP,
            SYS_DRIVER_REPLY_WAIT,
            // The vDSO clock (`vdso_now_ns`) falls back to SYS_UPTIME where
            // `rdtime` is not native.
            SYS_UPTIME,
            SYS_DRIVER_REGISTER_TYPED, SYS_CAP_LOOKUP,
            SYS_I2C_READ_TYPED, SYS_I2C_WRITE_TYPED,
        ],
        audit: false,
    },
    // RFC-0055 (wave 11): the user shell. The ONLY profile that lists
    // `SYS_CONSOLE_WAIT` (609, console input) and, with it, `SYS_SPAWN_EX`
    // (608) and `SYS_TASK_KILL` (611) — `tests/host/seccomp-tests` holds both
    // facts. No hardware or network call, no `SYS_FORK`/`SYS_EXEC*`/
    // `SYS_SPAWN`, no `SYS_GETCHAR`/`SYS_PUTCHAR`, no `SYS_SHUTDOWN`/
    // `SYS_REBOOT`: what it runs is authorised by the CHILD's row. The file
    // calls serve its builtins (`ls`, `cat`, `mkdir`, `rm`) and the
    // redirections it opens and moves to a child; 559/562 reap its jobs.
    ImageProfile {
        image: "SH.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_WRITE,
            SYS_STAT, SYS_READDIR, SYS_MKDIR, SYS_UNLINK,
            SYS_FILE_OPEN_TYPED, SYS_FILE_READ_TYPED, SYS_FILE_WRITE_TYPED, SYS_CLOSE_TYPED,
            SYS_WAIT_STATUS, SYS_WAITPID,
            SYS_PIPE_TYPED, SYS_SPAWN_EX, SYS_CONSOLE_WAIT, SYS_TASK_KILL,
            // Wave 13: the shell marks itself a child subreaper at start.
            SYS_TASK_SUBREAPER,
        ],
        audit: false,
    },
    // RFC-0055 (wave 11): the shell's multicall tool image. Reads and writes
    // the fds it was moved (564/565/566 on a `Cap<File>` or a `Cap<Pipe>`),
    // opens files read-only, lists directories, sleeps.
    ImageProfile {
        image: "TOOLBOX.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_WRITE, SYS_SLEEP, SYS_READDIR,
            SYS_FILE_OPEN_TYPED, SYS_FILE_READ_TYPED, SYS_FILE_WRITE_TYPED, SYS_CLOSE_TYPED,
        ],
        audit: false,
    },
    // RFC-0055 S5: the shell's power tool, the first privileged family with a
    // ring-3 form. The ONLY profile that lists `SYS_POWER_TYPED` (614);
    // `SYS_CAP_LOOKUP` finds the `Cap<Power>` its row grants. No
    // `SYS_SHUTDOWN`/`SYS_REBOOT` (270/271): the typed call is the narrower
    // form and the one whose refusals are recorded. 565: libsys `write` on an
    // fd the shell moved to it (a redirected stdout).
    ImageProfile {
        image: "POWER.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_WRITE, SYS_CAP_LOOKUP, SYS_POWER_TYPED,
            SYS_FILE_WRITE_TYPED,
        ],
        audit: false,
    },
    // Wave 12: the other privileged families' tools, the POWER.ELF shape:
    // each the ONLY profile that lists its family's typed call (615..=618),
    // `SYS_CAP_LOOKUP` for the capability its row grants, and 565 for a
    // redirected stdout.
    ImageProfile {
        image: "FLIGHT.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_WRITE, SYS_CAP_LOOKUP, SYS_FLIGHT_TYPED,
            SYS_FILE_WRITE_TYPED,
        ],
        audit: false,
    },
    ImageProfile {
        image: "BEHAVIOR.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_WRITE, SYS_CAP_LOOKUP, SYS_BEHAVIOR_TYPED,
            SYS_FILE_WRITE_TYPED,
        ],
        audit: false,
    },
    ImageProfile {
        image: "CONFIG.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_WRITE, SYS_CAP_LOOKUP, SYS_CONFIG_TYPED,
            SYS_FILE_WRITE_TYPED,
        ],
        audit: false,
    },
    ImageProfile {
        image: "OTA.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_WRITE, SYS_CAP_LOOKUP, SYS_OTA_TYPED,
            SYS_FILE_WRITE_TYPED,
        ],
        audit: false,
    },
    // Wave 15 (TRACE): the tracer's reader, the POWER.ELF shape. The ONLY
    // profile that lists `SYS_TRACE_CTL_TYPED` (632); `SYS_CAP_LOOKUP` finds
    // the `Cap<Trace>` its row grants; `SYS_SLEEP` between drains (the rings
    // are polled: the producer rings no doorbell); `SYS_UPTIME` where the
    // clock vDSO falls back to it (`rdtime` not native); 563/565/566 and 600
    // for `-o FILE` (and 565 for a redirected stdout).
    ImageProfile {
        image: "TRACECTL.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_WRITE, SYS_SLEEP, SYS_UPTIME, SYS_CAP_LOOKUP, SYS_TRACE_CTL_TYPED,
            SYS_FILE_OPEN_TYPED, SYS_FILE_WRITE_TYPED, SYS_CLOSE_TYPED, SYS_FSYNC_TYPED,
        ],
        audit: false,
    },
    // RFC-0053 L0/L0b: the Linux driver server skeleton. Reads its test
    // module off the boot volume (563/564/566), prints through libsys
    // `println` (1, its fallback), builds the two regions with
    // anonymous memory (`SYS_MMAP`), and is the ONLY profile that lists the
    // module pair (630/631; `tests/host/seccomp-tests` holds it there). Then
    // idles in `SYS_SLEEP`. No capability lookup: its topology row grants
    // none, and in particular no actuator. The two module calls exist only
    // in a kernel built with `lx-loader`; elsewhere they are -ENOSYS and the
    // row is simply never started (no topology row without `lx-server`).
    ImageProfile {
        image: "LXSRV.ELF",
        syscalls: sys_nrs![
            SYS_PUTCHAR, SYS_EXIT, SYS_WRITE, SYS_SLEEP, SYS_MMAP,
            SYS_FILE_OPEN_TYPED, SYS_FILE_READ_TYPED, SYS_CLOSE_TYPED,
            SYS_MODULE_VERIFY, SYS_MODULE_MAP_X,
            // RFC-0053 L1: the clock (jiffies for the lx/ base; the
            // comparison timing's trapping-syscall floor).
            SYS_UPTIME,
        ],
        audit: false,
    },
    // RFC-0047 (wave 12): the Linux personality's test binary, a static
    // Linux ELF (`userspace/tests/lxhello/lxhello.c`). It traps with LINUX
    // numbers; seccomp runs after translation, so this row lists the NATIVE
    // calls its Linux calls reach (`azos_linux_abi::TABLE`), derived from
    // the source by `tests/host/seccomp-tests`. No `SYS_CONSOLE_WAIT`, no
    // spawn, no hardware.
    ImageProfile {
        image: "LXHELLO.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_WRITE, SYS_BRK, SYS_MMAP, SYS_MUNMAP, SYS_SLEEP_UNTIL,
            SYS_STAT, SYS_READDIR,
            SYS_FILE_OPEN_TYPED, SYS_FILE_READ_TYPED, SYS_FILE_WRITE_TYPED, SYS_CLOSE_TYPED,
            SYS_PIPE_TYPED, SYS_WAITPID, SYS_WAIT_STATUS,
            // Stage 3: `clone` (fork shape) and `execve` of itself.
            SYS_FORK, SYS_EXECPATH,
            // Wave 13: `kill` of a child (the stop call's ancestry), and
            // `read` of a console lent to it.
            SYS_TASK_KILL, SYS_CONSOLE_WAIT,
            // Wave 13: `clone` also reaches the thread create (derived from
            // the personality's table: LXHELLO itself forks only).
            SYS_THREAD_CREATE,
            // Wave 15: `futex` (a robust lock's waiter, a parked thread).
            SYS_FUTEX_WAIT, SYS_FUTEX_WAKE,
        ],
        audit: false,
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
#[cfg(not(all(any(target_arch = "riscv64", target_arch = "aarch64"), target_os = "none")))]
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
#[cfg(not(all(any(target_arch = "riscv64", target_arch = "aarch64"), target_os = "none")))]
const THIRDPARTY_SHA256: &[(&str, [u8; 32])] = &[];

/// The rows of the third-party images (RFC-0047). Each lists the NATIVE
/// numbers its Linux calls reach through the personality, as a Linux image's
/// row does (seccomp after translation); `tests/host/seccomp-tests` holds every
/// number to one the personality's table can reach. Without the program built
/// the row binds nothing (its digest table is empty).
pub const THIRDPARTY_PROFILES: &[ImageProfile] = &[
    // BusyBox (`make busybox`, GPL-2.0-only, USERSPACE_GPL): `sh` (ash), the
    // applets it runs in a forked child, and `execve` of itself.
    ImageProfile {
        image: "BUSYBOX.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_WRITE, SYS_BRK, SYS_MMAP, SYS_MUNMAP, SYS_SLEEP_UNTIL, SYS_YIELD,
            SYS_STAT, SYS_READDIR,
            SYS_FILE_OPEN_TYPED, SYS_FILE_READ_TYPED, SYS_FILE_WRITE_TYPED, SYS_CLOSE_TYPED,
            SYS_PIPE_TYPED, SYS_WAITPID, SYS_WAIT_STATUS, SYS_FORK, SYS_EXECPATH,
            // Wave 13: `kill` (ash's builtin, its children only) and the
            // console the shell lends its foreground job (interactive `sh`).
            SYS_TASK_KILL, SYS_CONSOLE_WAIT,
        ],
        audit: false,
    },
    // Wave 13 (THREADS): `LXTHR.ELF` (`make lxthreads`), our own C linked
    // statically with musl by zig cc, built only beside the third-party
    // images for the same reason (an external toolchain). pthreads: `clone`
    // (thread shape), `futex`, `mmap`/`munmap` for the stacks, a `/tmp` file
    // two threads write.
    ImageProfile {
        image: "LXTHR.ELF",
        syscalls: sys_nrs![
            SYS_EXIT, SYS_WRITE, SYS_BRK, SYS_MMAP, SYS_MUNMAP, SYS_YIELD,
            SYS_FILE_OPEN_TYPED, SYS_FILE_READ_TYPED, SYS_FILE_WRITE_TYPED, SYS_CLOSE_TYPED,
            SYS_STAT, SYS_READDIR,
            SYS_THREAD_CREATE, SYS_FUTEX_WAIT, SYS_FUTEX_WAKE,
            // Wave 13 (SIGNALS): sleeps between steps, and a threaded child
            // (fork, wait) ended by a signal.
            SYS_SLEEP_UNTIL, SYS_FORK, SYS_WAITPID, SYS_WAIT_STATUS,
        ],
        audit: false,
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
    filter
}

/// The calls a `mem = "locked"` task may never make (RFC-0049 P2): a fork puts
/// every page under copy-on-write, and a demand reservation faults on first
/// touch. A locked task must take no page fault.
pub const LOCKED_FORBIDDEN: [u16; 3] = [
    azos_abi::syscall_nr::SYS_FORK as u16,
    azos_abi::syscall_nr::SYS_FORK_COW as u16,
    azos_abi::syscall_nr::SYS_ALLOC_DEMAND as u16,
];

/// May an image run under a `mem = "locked"` topology row?
///
/// P2: its profile has none of [`LOCKED_FORBIDDEN`], and it is not in audit
/// mode — an audit-mode profile lets an unlisted call through, so it cannot
/// promise the absence of anything. The loaders refuse a locked row whose
/// image fails this; the fork and demand handlers also refuse a locked task
/// outright, so the profile is not the only line.
pub fn locked_compatible(p: &ImageProfile) -> bool {
    !p.audit && !p.syscalls.iter().any(|n| LOCKED_FORBIDDEN.contains(n))
}

/// Can an image with this profile fork (RFC-0049 M1, wave 9)? It lists
/// `SYS_FORK` or `SYS_FORK_COW`, or it is in audit mode, which lets an
/// unlisted call through. Memory admission counts a row whose image can fork
/// twice (one COW copy per instance) and a row whose image cannot, once.
pub fn profile_can_fork(p: &ImageProfile) -> bool {
    p.audit
        || p.syscalls.iter().any(|&n| {
            n == azos_abi::syscall_nr::SYS_FORK as u16
                || n == azos_abi::syscall_nr::SYS_FORK_COW as u16
        })
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
/// [`SECCOMP_E_ALREADY`] and installs nothing. Ring-3 `SYS_EXEC` and
/// `SYS_EXECPATH` do not come here: after a successful exec they install the
/// executed image's own filter directly (`azos_syscall::handlers`, the
/// `set_current_syscall_filter` call after `exec_user`), so the task runs
/// under the row bound to the image it now is, not the one it was. That
/// filter can be wider than the caller's when the caller's row allows exec.
///
/// Returns 0 when the row's filter is installed.
pub fn install_image_profile(p: &ImageProfile) -> i64 {
    if crate::scheduler::current_syscall_filter().enabled {
        return SECCOMP_E_ALREADY;
    }
    crate::scheduler::set_current_syscall_filter(image_filter(p));
    0
}

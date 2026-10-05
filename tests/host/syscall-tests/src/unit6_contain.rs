// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Degraded-mode containment on the untyped twins, and the per-task bound on
// capability-denial records. Two audit findings, 2026-09-13.
//
// ── F1: the untyped door to a contained write ─────────────────────────────
//
// Containment lived in `CapTable::get` and `holds_kind_resource_with`, so a
// task whose typed write was refused while degraded made the same write
// through the untyped call on the same fd, socket, pin or channel. Owner
// decision 2026-09-13: every WRITE through a capability is refused, files and
// sockets included; receiving, closing and releasing stay live (see "Releases
// and motors" below).
//
// The twins, found by walking `CAP_TYPED_SYSCALLS` and asking of each typed
// handler whether it resolves with WRITE:
//
// | typed (needs WRITE)              | untyped twin                        | here            |
// |----------------------------------|-------------------------------------|-----------------|
// | FILE_WRITE_TYPED 565             | sys_write, fd >= 3                  | contained       |
// | SEND_TYPED 569                   | sys_send_syscall, sys_sendto_syscall| contained       |
// | CONNECT_TYPED 568                | sys_connect_syscall                 | contained       |
// | GPIO/I2C/PWM writes 540-549      | none (200-213, 221 retired, gap 1)  | typed_twin_guards.rs |
// | CHAN_WRITE_TYPED 528             | none (101, 507 retired, gap 1)      | typed_ipc.rs    |
// | DRIVER_REGISTER_TYPED 556        | none (520 retired, gap 1)           | contained       |
// | IORING_SUBMIT_TYPED 537          | none (504 retired, gap 1)           | —               |
// | none                             | sys_motor_create                    | ring 3 refused  |
// | MOTOR_SET_TARGET/TICK/ENABLE/    | none — a disjoint surface           | —               |
// |   SET_GAINS/RESET_TYPED 550-555  |                                     |                 |
// | MCAST_JOIN_TYPED 571             | SYS_MCAST_JOIN is a stub            | —               |
//
// Deliberately live: fd 1/2 (the console), every receive, every close,
// `sys_i2c_scan` (its typed twin `I2C_DETECT_TYPED` is a READ), and every
// kernel-context caller.
//
// ── Releases and motors (owner decisions, 2026-09-13) ─────────────────────
//
// Releasing an object is exempt from containment and keeps its authority:
//
// | typed (release)                  | untyped twin                        | while contained |
// |----------------------------------|-------------------------------------|-----------------|
// | PORT_DESTROY_TYPED 532 (WRITE)   | none (514 retired, gap 1)           | live            |
// | IORING_DESTROY_TYPED 538 (WRITE) | none                                | live            |
// | DRIVER_UNREGISTER_TYPED 557 (W)  | none (521 retired, gap 1)           | live            |
// | SHM_RELEASE_TYPED 535 (READ)     | none                                | live, unchanged |
// | CLOSE_TYPED 564, MCAST_LEAVE 572 | sys_close, sys_sock_close           | live, unchanged |
// | CLOSE_TYPED 566 on a Channel (W) | none (107 retired, gap 1)           | live            |
//
// Motors: while an e-stop is latched or containment is armed, brake and coast
// are carried out and forward and backward are refused in `motor_set_reporting`
// without writing the direction pins. `MOTOR_SPEED_TYPED 560` and
// `MOTOR_DIRECTION_TYPED 576` reach that one refusal, and the kernel's own
// control loop does too. The PID calls 550-555 (bar the READ 553) stay
// contained: none of them leaves a wheel stopped.
//
// Observing "admitted" on a host: the GPIO and PWM drivers take installable
// probes; the console and the I2C bus scan reach an MMIO `todo!()`, so
// `#[should_panic]` on its message IS the assertion; sockets and IPC take a
// non-null address in an empty user page table, so an admitted call fails its
// copy with `-1` where a contained one answers `-EAGAIN` before copying.
//
// ── F2: a flood of denial records ─────────────────────────────────────────
//
// Both recorders reach only the in-memory ring, which overwrites its oldest
// record. A ring-3 loop of forged handles pushed one record per syscall and
// evicted the ring-only safety records next to it. The tests drive the real
// `cap_check` and `errno_for_gpio_err` against a hand-driven clock and read
// back, in order, everything the three hooks saw.

use super::harness::serial;
use crate::ipc_handlers::*;
use azos_abi::error::Errno;
use azos_arch_api::PagePerms;
use azos_drv_gpio::gpio::{set_gpio_probe, GpioOp};
use azos_drv_actuator::pwm::{set_pwm_probe, PwmOp};
use azos_ipc::cap::CapError;
use azos_abi::cap::{CapKind, CapPerms};
use azos_ipc::gpio_cap::GpioCapError;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

// ── The caller ────────────────────────────────────────────────────────────

/// TIDs nothing else in the crate uses, so a table one test filled is never
/// read by another.
static NEXT_TID: AtomicU32 = AtomicU32::new(0x7600_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

/// A page mapped user-RW in the caller's page table.
const SCRATCH: usize = 0x0074_0000;
/// A non-null address no test here ever maps: a copy from it fails.
const UNMAPPED: u64 = 0x0078_0000;
/// A driver kind clear of every real `DRV_KIND_*` and of
/// `driver_server_guards.rs`'s `0x91xx` values.
const DRV_KIND: u32 = 0x9130;
/// The kind the typed registry calls below name, beside `DRV_KIND`.
const DRV_KIND_TYPED: u32 = 0x9131;

fn eagain() -> i64 {
    Errno::EAGAIN.to_syscall_ret()
}

/// Puts back every process static a test here can touch, panic or not.
struct Scene {
    tid: u32,
}

impl Drop for Scene {
    fn drop(&mut self) {
        azos_ipc::cap::degraded_set(false);
        ESTOP.store(false, Ordering::SeqCst);
        __cap_deny_limiter_clear_for_tests();
        set_gpio_probe(None);
        set_pwm_probe(None);
        let _ = azos_driver_server::driver_unregister(DRV_KIND_TYPED);
        azos_robot::motor::shim_clear_motor_pins();
        azos_robot::motor::shim_clear_motor_channels();
        crate::file_ops::__file_ops_clear_for_tests();
        let _ = azos_driver_server::driver_unregister(DRV_KIND);
        for fd in 0..azos_net::MAX_SOCKETS as i32 {
            if azos_net::socket_owner(fd) == Some(self.tid) {
                azos_net::socket_close(fd);
            }
        }
        azos_ipc::cap_store::reset(self.tid);
    }
}

/// `tid` as a ring-3 caller with a real, empty page table (every copy from a
/// user address fails unless the test maps one) and an empty capability table
/// at `SLOT`.
///
/// Two task tables: `cap_store` resolves TIDs through `ipc_task_pool`, the
/// handlers ask this crate's `shims/sched`. See `gpio_typed_lock.rs`.
fn ring3(tid: u32) -> Scene {
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(tid);
    Scene { tid }
}

/// Map `SCRATCH` in the current page table.
fn map_scratch() {
    let pt = azos_sched::current_user_pt();
    let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, SCRATCH, phys, PagePerms::USER_RW).expect("map");
}

/// Grant `tid` a capability of `kind` for `resource` straight into its table:
/// the object an untyped call's `cap_check` names.
fn hold(tid: u32, kind: CapKind, resource: u32, perms: CapPerms) {
    assert!(
        azos_ipc::cap_store::with_table(tid, |t| t.grant_raw(kind, perms, resource))
            .flatten()
            .is_some(),
        "could not grant {kind:?} {resource:#x} to {tid:#x}"
    );
}

// ── A filesystem that only counts writes ──────────────────────────────────

static WRITES: Mutex<Vec<(i32, usize)>> = Mutex::new(Vec::new());

fn writes() -> Vec<(i32, usize)> {
    WRITES.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

struct Disk;

impl crate::file_ops::FileOps for Disk {
    fn open(&self, _path: &[u8], _flags: u32) -> i64 { -1 }
    fn close(&self, _fd: i32) -> i64 { -1 }
    fn read(&self, _fd: i32, _dst: &mut [u8]) -> i64 { -1 }
    fn write(&self, fd: i32, src: &[u8]) -> i64 {
        WRITES.lock().unwrap_or_else(|e| e.into_inner()).push((fd, src.len()));
        src.len() as i64
    }
    fn lseek(&self, _fd: i32, _offset: i64, _whence: i32) -> i64 { -1 }
    fn dup(&self, _fd: i32) -> i64 { -1 }
    fn dup2(&self, _oldfd: i32, _newfd: i32) -> i64 { -1 }
    fn mkdir(&self, _path: &[u8]) -> i64 { -1 }
    fn unlink(&self, _path: &[u8]) -> i64 { -1 }
    fn readdir(&self, _path: &[u8], _index: u32) -> Option<([u8; 64], u32, bool)> { None }
    fn release_all(&self, _tid: u32) -> usize { 0 }
    fn read_whole(&self, _path: &[u8], _dst: &mut [u8]) -> usize { 0 }
}

static DISK: Disk = Disk;

fn install_disk() {
    WRITES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    crate::file_ops::set_file_ops(&DISK);
}

// ── A GPIO driver that only counts calls ──────────────────────────────────

static GPIO_CALLS: Mutex<Vec<(GpioOp, u32, u32)>> = Mutex::new(Vec::new());

fn gpio_probe(op: GpioOp, pin: u32, arg: u32) -> i32 {
    GPIO_CALLS.lock().unwrap_or_else(|e| e.into_inner()).push((op, pin, arg));
    0
}

fn gpio_calls() -> Vec<(GpioOp, u32, u32)> {
    GPIO_CALLS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn install_gpio_probe() {
    GPIO_CALLS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_gpio_probe(Some(gpio_probe));
}

// ═════════════════════════════════════════════════════════════════════════
// F1 — containment
// ═════════════════════════════════════════════════════════════════════════

/// A file write is refused while contained and reaches the filesystem again
/// once containment clears.
///
/// **Canary.** Delete the check from `sys_write`: the first assertion reads 4.
#[test]
fn a_file_write_is_contained_and_live_once_cleared() {
    let _g = serial();
    let _s = ring3(fresh_tid());
    map_scratch();
    install_disk();

    azos_ipc::cap::degraded_set(true);
    assert_eq!(sys_write(7, SCRATCH as u64, 4), eagain(), "a file write went through containment");
    assert!(writes().is_empty(), "the filesystem saw {:?} while contained", writes());

    azos_ipc::cap::degraded_set(false);
    assert_eq!(sys_write(7, SCRATCH as u64, 4), 4, "clearing containment did not re-open the write");
    assert_eq!(writes(), vec![(7, 4)]);
}

/// **The console stays live.** A write to fd 1 while contained reaches the
/// UART, whose stand-in panics — so the panic IS the assertion.
///
/// **Canary.** Move the check above the fd 1/2 arm: the call returns `-EAGAIN`
/// and never panics.
#[test]
#[should_panic(expected = "MMIO stand-in")]
fn stdout_is_not_contained() {
    let _g = serial();
    let _s = ring3(fresh_tid());
    map_scratch();
    install_disk();
    azos_ipc::cap::degraded_set(true);
    let r = sys_write(1, SCRATCH as u64, 4);
    panic!("stdout did not reach the console while contained: returned {r}");
}

/// fd 2, the same arm.
#[test]
#[should_panic(expected = "MMIO stand-in")]
fn stderr_is_not_contained() {
    let _g = serial();
    let _s = ring3(fresh_tid());
    map_scratch();
    install_disk();
    azos_ipc::cap::degraded_set(true);
    let r = sys_write(2, SCRATCH as u64, 4);
    panic!("stderr did not reach the console while contained: returned {r}");
}

/// Send, sendto (with and without an address) and connect are refused while
/// contained; each gets past the check once containment clears, where the copy
/// from an unmapped address fails with `-1`. Receive and close stay live.
///
/// **Canary.** Delete the check from any one of the three handlers: its
/// assertion reads `-1`.
#[test]
fn socket_writes_are_contained_and_receive_and_close_stay_live() {
    let _g = serial();
    let _s = ring3(fresh_tid());
    let fd = sys_socket(
        azos_net::socket::AF_INET as u64,
        azos_net::socket::SOCK_DGRAM as u64,
        azos_net::socket::IPPROTO_UDP as u64,
    );
    assert!(fd >= 0, "socket returned {fd}");
    let fd = fd as u64;

    azos_ipc::cap::degraded_set(true);
    assert_eq!(sys_send_syscall(fd, UNMAPPED, 4, 0), eagain(), "send");
    assert_eq!(sys_sendto_syscall(fd, UNMAPPED, 4, 0), eagain(), "sendto without an address");
    assert_eq!(sys_sendto_syscall(fd, UNMAPPED, 4, UNMAPPED), eagain(), "sendto with an address");
    assert_eq!(sys_connect_syscall(fd, UNMAPPED, 16), eagain(), "connect");
    // Receive: the null-buffer guard answers, not containment.
    assert_eq!(sys_recv_syscall(fd, 0, 4, 0), -1, "receive");
    assert_eq!(sys_recvfrom_syscall(fd, 0, 4, 0), -1, "recvfrom");

    azos_ipc::cap::degraded_set(false);
    assert_eq!(sys_send_syscall(fd, UNMAPPED, 4, 0), -1, "send did not reach its copy");
    assert_eq!(sys_sendto_syscall(fd, UNMAPPED, 4, 0), -1, "sendto did not reach its copy");
    assert_eq!(sys_sendto_syscall(fd, UNMAPPED, 4, UNMAPPED), -1, "sendto did not reach its address");
    assert_eq!(sys_connect_syscall(fd, UNMAPPED, 16), -1, "connect did not reach its address");

    azos_ipc::cap::degraded_set(true);
    assert_eq!(sys_sock_close(fd), 0, "containment blocked the close");
}

/// `sys_i2c_scan` asks `cap_check` for write, but its typed twin
/// `I2C_DETECT_TYPED` resolves with READ, so it stays live.
#[test]
#[should_panic(expected = "MMIO stand-in")]
fn i2c_scan_is_not_contained() {
    let _g = serial();
    let s = ring3(fresh_tid());
    hold(s.tid, CapKind::I2c, 0, CapPerms::RW);
    azos_ipc::cap::degraded_set(true);
    let r = sys_i2c_scan(0);
    panic!("i2c_scan did not reach the driver while contained: returned {r}");
}

/// Registering a driver is refused while contained; unregistering is a release
/// and goes through, and still needs `WRITE`. Each step is read back through
/// the registry: a register that succeeds proves the kind was free, so a
/// contained register did not claim it and a contained unregister did release
/// it.
///
/// **Canaries.** Resolve `sys_driver_unregister_typed` with `drvreg_kind_of`:
/// the contained unregister reads `-EAGAIN`. Resolve
/// `sys_driver_register_typed` with `drvreg_kind_for_release`: the contained
/// register reads 0.
#[test]
fn driver_register_is_contained_and_unregister_is_live() {
    use azos_abi::cap::CapPerms;
    use azos_ipc::cap::targets::DriverRegistry;
    let _g = serial();
    let tid = fresh_tid();
    let _s = ring3_with_table(tid);
    let cap = held::<DriverRegistry>(tid, CapPerms::RW, DRV_KIND_TYPED);
    let read_only = held::<DriverRegistry>(tid, CapPerms::READ, DRV_KIND_TYPED);

    azos_ipc::cap::degraded_set(true);
    assert_eq!(sys_driver_register_typed(cap, 0, 0, 0), eagain(), "typed register while contained");
    azos_ipc::cap::degraded_set(false);
    assert_eq!(sys_driver_register_typed(cap, 0, 0, 0), 0, "the contained typed register claimed the kind");
    azos_ipc::cap::degraded_set(true);
    assert_eq!(
        sys_driver_unregister_typed(read_only),
        Errno::ECAPPERMS.to_syscall_ret(),
        "a READ-only capability unregistered while contained"
    );
    assert_eq!(sys_driver_unregister_typed(cap), 0, "typed unregister while contained");
    azos_ipc::cap::degraded_set(false);
    assert_eq!(sys_driver_register_typed(cap, 0, 0, 0), 0, "the contained typed unregister did not release the kind");
}

/// **A caller that does not hold the object keeps its usual refusal.**
/// Containment runs after the authority check, so it tells a stranger nothing.
///
/// **Canary.** Move the check above `socket_access_ok` in `sys_send_syscall`:
/// the first assertion reads `-EAGAIN`.
#[test]
fn an_unheld_object_keeps_its_own_refusal_while_contained() {
    let _g = serial();
    let s = ring3(fresh_tid());

    // A socket some other task owns.
    let other = fresh_tid();
    azos_sched::set_current_task_tid(other);
    let theirs = sys_socket(
        azos_net::socket::AF_INET as u64,
        azos_net::socket::SOCK_DGRAM as u64,
        azos_net::socket::IPPROTO_UDP as u64,
    );
    assert!(theirs >= 0);
    azos_sched::set_current_task_tid(s.tid);
    let _other = Scene { tid: other };

    azos_ipc::cap::degraded_set(true);
    let theirs = theirs as u64;
    assert_eq!(sys_send_syscall(theirs, UNMAPPED, 4, 0), -1, "send");
    assert_eq!(sys_sendto_syscall(theirs, UNMAPPED, 4, UNMAPPED), -1, "sendto");
    assert_eq!(sys_connect_syscall(theirs, UNMAPPED, 16), -1, "connect");
}

/// **A kernel-context caller is not contained.** It holds no capability, and
/// the way out of containment is on the kernel's side: the predicate the
/// untyped writes ask answers false for `user_pt == 0` while degraded, true for
/// ring 3, and a kernel file write reaches the filesystem while contained.
///
/// **Canary.** Drop `current_user_pt() != 0` from `untyped_write_contained`:
/// the kernel-context assertion fails.
#[test]
fn a_kernel_caller_is_not_contained() {
    let _g = serial();
    let _s = Scene { tid: 0 };
    install_disk();
    azos_ipc::cap::degraded_set(true);
    azos_sched::set_current_user_pt(0);
    assert!(!untyped_write_contained(), "a kernel-context write was contained");
    let buf = [0x5Au8; 4];
    assert_eq!(sys_write(7, buf.as_ptr() as u64, 4), 4, "a kernel-context file write was refused");
    assert_eq!(writes(), vec![(7, 4)]);

    azos_sched::set_current_user_pt(0xBAD0_0000);
    assert!(untyped_write_contained(), "precondition: a ring-3 write is contained");
}

// ═════════════════════════════════════════════════════════════════════════
// F2 — the per-task bound on denial records
// ═════════════════════════════════════════════════════════════════════════

/// Everything the three hooks saw, in order. The TID is read at the moment of
/// the call, which is the task the kernel would have been running.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Seen {
    Untyped { tid: u32, kind: u8, detail: u32 },
    Typed { tid: u32, kind: u8, reason: u32 },
    Summary { kind: u8, count: u32 },
    /// A syscall an audit-mode seccomp filter let through (`record_seccomp_audit`).
    Audit { tid: u32, nr: u16 },
}

static SEEN: Mutex<Vec<Seen>> = Mutex::new(Vec::new());

fn push(e: Seen) {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).push(e);
}

fn audit_hook(nr: u16) {
    let tid = azos_sched::current_task_tid();
    push(Seen::Audit { tid, nr });
}

/// Seccomp audit records written while `tid` was running.
fn audits_of(tid: u32) -> usize {
    seen().iter().filter(|e| matches!(e, Seen::Audit { tid: t, .. } if *t == tid)).count()
}

fn untyped_hook(kind: u8, target: u32, need_write: bool) {
    let tid = azos_sched::current_task_tid();
    push(Seen::Untyped { tid, kind, detail: target | if need_write { 0x8000_0000 } else { 0 } });
}

fn typed_hook(kind: u8, reason: u32) {
    let tid = azos_sched::current_task_tid();
    push(Seen::Typed { tid, kind, reason });
}

fn summary_hook(kind: u8, count: u32) {
    push(Seen::Summary { kind, count });
}

fn seen() -> Vec<Seen> {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Records (not summaries) written while `tid` was running.
fn records_of(tid: u32) -> usize {
    seen()
        .iter()
        .filter(|e| matches!(e, Seen::Untyped { tid: t, .. } | Seen::Typed { tid: t, .. } if *t == tid))
        .count()
}

fn summaries() -> Vec<(u8, u32)> {
    seen()
        .iter()
        .filter_map(|e| match *e { Seen::Summary { kind, count } => Some((kind, count)), _ => None })
        .collect()
}

static NOW: AtomicU64 = AtomicU64::new(0);
const WINDOW: u64 = 1_000;

fn clock() -> u64 {
    NOW.load(Ordering::SeqCst)
}

fn set_now(t: u64) {
    NOW.store(t, Ordering::SeqCst);
}

/// Install all three hooks with the hand-driven clock at 0, on an empty table.
fn arm_limiter() {
    __cap_deny_limiter_clear_for_tests();
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_now(0);
    set_cap_deny_recorder(untyped_hook);
    set_cap_deny_typed_recorder(typed_hook);
    set_cap_deny_limiter(clock, WINDOW, summary_hook);
}

/// Become `tid`, an unprivileged caller holding nothing. `cap_check` never
/// dereferences the page table, so a sentinel is enough.
fn become_user(tid: u32) {
    azos_sched::set_current_user_pt(0xBAD0_0000);
    azos_sched::set_current_task_tid(tid);
}

fn gpio_denial(pin: u32) {
    assert!(!cap_check(CapKind::Gpio, pin, true), "the caller was not denied");
}

fn typed_gpio_denial() {
    let _ = errno_for_gpio_err(GpioCapError::Cap(CapError::Stale));
}

const GPIO: u8 = 2;

/// A flood is cut to the bound, and the count that comes out when its window
/// closes is exactly the number suppressed — written before the record that
/// closed the window.
///
/// **Canary.** Drop the summary call from `admit_denial_record`: `summaries()`
/// is empty.
#[test]
fn a_flood_is_bounded_and_its_summary_counts_every_suppressed_denial() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene { tid: a };
    arm_limiter();
    become_user(a);

    for _ in 0..20 {
        gpio_denial(7);
    }
    assert_eq!(records_of(a), DENIAL_RECORDS_PER_WINDOW as usize, "the flood was not bounded");
    assert!(summaries().is_empty(), "a summary came out of a window still open");

    set_now(WINDOW);
    gpio_denial(7);
    assert_eq!(summaries(), vec![(GPIO, 16)], "20 denials, 4 recorded: 16 suppressed");
    let tail = seen();
    assert_eq!(
        &tail[tail.len() - 2..],
        &[
            Seen::Summary { kind: GPIO, count: 16 },
            Seen::Untyped { tid: a, kind: GPIO, detail: 7 | 0x8000_0000 },
        ],
        "the summary must precede the record that closed its window"
    );
}

/// **Per task.** Task B's denials in the same window as A's flood are all
/// recorded.
///
/// **Canary.** Match every entry regardless of TID in `admit_denial_record`:
/// B's records are suppressed.
#[test]
fn another_tasks_denials_are_not_suppressed_by_a_flood() {
    let _g = serial();
    let a = fresh_tid();
    let b = fresh_tid();
    let _s = Scene { tid: a };
    arm_limiter();

    become_user(a);
    for _ in 0..20 {
        gpio_denial(7);
    }
    become_user(b);
    for _ in 0..3 {
        gpio_denial(8);
    }
    assert_eq!(records_of(b), 3, "task A's flood suppressed task B's denials");
    assert!(summaries().is_empty());

    become_user(a);
    gpio_denial(7);
    assert_eq!(records_of(a), 4, "task B's denials refilled task A's budget");
}

/// **A flood that stops.** Its count comes out through the periodic flush once
/// its window is over — not before, and not twice.
///
/// **Canary.** Empty `cap_denial_flush_pending`: the second flush yields
/// nothing.
#[test]
fn a_flood_that_stops_yields_its_summary_through_the_flush() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene { tid: a };
    arm_limiter();
    become_user(a);

    for _ in 0..10 {
        gpio_denial(7);
    }
    azos_sched::set_current_task_tid(0); // the watchdog, not the flooder

    set_now(WINDOW - 1);
    cap_denial_flush_pending();
    assert!(summaries().is_empty(), "the flush wrote a count whose window was still open");

    set_now(WINDOW);
    cap_denial_flush_pending();
    assert_eq!(summaries(), vec![(GPIO, 6)]);

    set_now(3 * WINDOW);
    cap_denial_flush_pending();
    assert_eq!(summaries(), vec![(GPIO, 6)], "the same count was written twice");
}

/// **A task that exits mid-flood** has its count written by the exit hook,
/// whatever its window, and its next incarnation (a fresh TID in the kernel;
/// the same one here) starts a fresh budget.
///
/// **Canary.** Drop the summary call from `cap_denial_task_exit`: nothing comes
/// out.
#[test]
fn task_exit_writes_the_pending_summary() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene { tid: a };
    arm_limiter();
    become_user(a);

    for _ in 0..7 {
        gpio_denial(7);
    }
    azos_sched::set_current_task_tid(0);
    cap_denial_task_exit(a);
    assert_eq!(summaries(), vec![(GPIO, 3)]);
    cap_denial_task_exit(a);
    assert_eq!(summaries(), vec![(GPIO, 3)], "exit wrote the same count twice");

    become_user(a);
    gpio_denial(7);
    assert_eq!(records_of(a), 5, "the freed entry did not start a fresh budget");
}

/// **The gate's readback.** `captest` produces one untyped and one typed GPIO
/// denial; both must be recorded, and nothing summarised.
#[test]
fn the_captest_shape_records_both_denials() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene { tid: a };
    arm_limiter();
    become_user(a);

    gpio_denial(5);
    typed_gpio_denial();
    assert_eq!(
        seen(),
        vec![
            Seen::Untyped { tid: a, kind: GPIO, detail: 5 | 0x8000_0000 },
            Seen::Typed { tid: a, kind: GPIO, reason: CapError::Stale.code() },
        ]
    );
    set_now(WINDOW);
    cap_denial_flush_pending();
    assert!(summaries().is_empty());
}

/// Typed and untyped denials spend one budget, and a count that spans two kinds
/// is written as `DENIAL_KIND_MIXED`.
#[test]
fn typed_and_untyped_share_one_budget_and_mixed_kinds_are_marked() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene { tid: a };
    arm_limiter();
    become_user(a);

    gpio_denial(5);
    gpio_denial(5);
    typed_gpio_denial();
    typed_gpio_denial();
    assert_eq!(records_of(a), 4);

    typed_gpio_denial(); // suppressed, GPIO
    assert!(!cap_check(CapKind::Pwm, 1, true)); // suppressed, PWM
    assert_eq!(records_of(a), 4, "the typed path has a budget of its own");

    set_now(WINDOW);
    cap_denial_flush_pending();
    assert_eq!(summaries(), vec![(DENIAL_KIND_MIXED, 2)]);
}

/// **A containment refusal spends nothing.** It is not recorded, typed or
/// untyped, and a task retrying a contained write still has its whole budget
/// for real denials.
///
/// **Canary.** Call `admit_denial_record` before the `is_denial()` filter in
/// `note_typed_denial`: the four real denials are suppressed.
#[test]
fn containment_refusals_do_not_spend_the_budget() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene { tid: a };
    arm_limiter();
    become_user(a);
    install_disk();
    ipc_task_pool::shim_bind(a, SLOT);
    azos_ipc::cap_store::reset(a);
    // A real page table with `SCRATCH` mapped, so the untyped file write copies
    // its buffer and reaches the containment check.
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::set_current_user_pt(pt);
    map_scratch();

    azos_ipc::cap::degraded_set(true);
    for _ in 0..10 {
        assert_eq!(errno_for_gpio_err(GpioCapError::Cap(CapError::Contained)), eagain());
        assert_eq!(sys_write(7, SCRATCH as u64, 4), eagain());
    }
    assert!(writes().is_empty(), "the filesystem saw {:?} while contained", writes());
    assert!(seen().is_empty(), "a containment refusal was recorded: {:?}", seen());

    for _ in 0..4 {
        gpio_denial(9);
    }
    assert_eq!(records_of(a), 4, "containment refusals spent the budget");
    set_now(WINDOW);
    cap_denial_flush_pending();
    assert!(summaries().is_empty());
}

/// **Eviction does not drop a count.** With every entry taken and none
/// expired, a new TID takes the oldest entry, and that entry's count is written
/// out first.
#[test]
fn an_evicted_entry_writes_its_count_first() {
    let _g = serial();
    let first = fresh_tid();
    let _s = Scene { tid: first };
    arm_limiter();

    become_user(first);
    for _ in 0..6 {
        gpio_denial(7);
    }
    for _ in 1..DENIAL_BUCKETS {
        become_user(fresh_tid());
        gpio_denial(7);
    }
    assert!(summaries().is_empty());

    set_now(1);
    become_user(fresh_tid());
    gpio_denial(7);
    assert_eq!(summaries(), vec![(GPIO, 2)], "the evicted entry's count was lost");
}

// ═════════════════════════════════════════════════════════════════════════
// Seccomp audit records take the same per-task bound, with a budget of their own
// ═════════════════════════════════════════════════════════════════════════

/// **Bounded.** A loop of syscalls an audit-mode filter lets through writes at
/// most `DENIAL_RECORDS_PER_WINDOW` audit records per window, and the rest come
/// out as one summary under `DENIAL_KIND_SECCOMP_AUDIT`.
///
/// **Canary.** Call the recorder without `admit_denial_record` in
/// `record_seccomp_audit`: twenty records, no summary.
#[test]
fn a_flood_of_audited_calls_is_bounded_and_summarised_under_its_own_kind() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene { tid: a };
    arm_limiter();
    set_seccomp_audit_recorder(audit_hook);
    become_user(a);

    for _ in 0..20 {
        record_seccomp_audit(999);
    }
    assert_eq!(audits_of(a), DENIAL_RECORDS_PER_WINDOW as usize, "the audit flood was not bounded");
    assert!(seen().contains(&Seen::Audit { tid: a, nr: 999 }), "the record must carry the syscall number");
    assert!(summaries().is_empty(), "a summary came out of a window still open");

    set_now(WINDOW);
    cap_denial_flush_pending();
    assert_eq!(summaries(), vec![(DENIAL_KIND_SECCOMP_AUDIT, 16)]);
    __seccomp_audit_recorder_clear_for_tests();
}

/// **Separate budgets, one window.** A task's capability denials and its audit
/// records each get `DENIAL_RECORDS_PER_WINDOW`: four of each are written, the
/// fifth of each is counted, and each class comes out as its own summary under
/// its own kind (capability class first).
///
/// **Canary.** Map every kind to class 0 in `denial_class`: eight admits fit a
/// single budget of four.
#[test]
fn audited_calls_and_capability_denials_have_separate_budgets() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene { tid: a };
    arm_limiter();
    set_seccomp_audit_recorder(audit_hook);
    become_user(a);

    for _ in 0..4 {
        gpio_denial(5);
        record_seccomp_audit(116);
    }
    assert_eq!(records_of(a), 4, "capability denials were starved");
    assert_eq!(audits_of(a), 4, "audit records were starved by capability denials");

    record_seccomp_audit(116); // suppressed, audit
    gpio_denial(5); // suppressed, GPIO
    assert_eq!(records_of(a) + audits_of(a), 8, "a fifth record of a class was written");

    set_now(WINDOW);
    cap_denial_flush_pending();
    assert_eq!(summaries(), vec![(GPIO, 1), (DENIAL_KIND_SECCOMP_AUDIT, 1)]);
    assert_ne!(DENIAL_KIND_SECCOMP_AUDIT, DENIAL_KIND_MIXED);
    __seccomp_audit_recorder_clear_for_tests();
}

/// **The gate-40 shape.** `captest` makes 13 capability denial admits (two
/// untyped, eleven typed; `userspace/tests/captest/src/main.rs`) in one window before
/// it issues syscall 116 under its audit profile. The audit record of 116 must
/// still be written, and so must a ring-3 exec refusal after it: a capability
/// flood cannot silence the other classes. Its own denials are still cut at four.
///
/// The untyped probe the kernel's `cap-deny-smoke` reads back is an ADC
/// refusal since the untyped check moved onto the capability table (autorun
/// holds `gpio.0` under `cap-refusal-canary`); every capability kind shares
/// class 0, so the budget arithmetic is the same.
///
/// **Canary.** Map every kind to class 0 in `denial_class`: the audit record of
/// 116 is suppressed.
#[test]
fn a_capability_flood_does_not_silence_the_audit_or_exec_records() {
    static EXEC_RECORDS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    fn exec_hook(_action: u8, _head: u32) {
        EXEC_RECORDS.fetch_add(1, Ordering::SeqCst);
    }

    let _g = serial();
    let a = fresh_tid();
    let _s = Scene { tid: a };
    arm_limiter();
    set_seccomp_audit_recorder(audit_hook);
    set_exec_refused_recorder(exec_hook);
    EXEC_RECORDS.store(0, Ordering::SeqCst);
    become_user(a);

    assert!(!cap_check(CapKind::Adc, 0, false)); // adc_read(0) [ungranted]
    gpio_denial(9); // stands in for motor_speed(9, 0) [ungranted id]: one more untyped admit
    for _ in 0..11 {
        typed_gpio_denial(); // forged, stale and read-only typed refusals
    }
    assert_eq!(records_of(a), DENIAL_RECORDS_PER_WINDOW as usize, "the capability flood was not bounded");

    record_seccomp_audit(116);
    assert_eq!(
        seen().iter().filter(|e| matches!(e, Seen::Audit { tid, nr: 116 } if *tid == a)).count(),
        1,
        "the audit record of syscall 116 was suppressed by the task's capability denials",
    );
    assert!(!exec_image_is_bound(b"bytes no image profile is bound to"));
    assert_eq!(EXEC_RECORDS.load(Ordering::SeqCst), 1, "the exec refusal was suppressed");

    set_now(WINDOW);
    cap_denial_flush_pending();
    assert_eq!(summaries(), vec![(GPIO, 9)], "only the capability class suppressed anything");
    __seccomp_audit_recorder_clear_for_tests();
    __exec_refused_recorder_clear_for_tests();
}

/// **No recorder, no spending.** Before the kernel installs the audit recorder
/// an audited call is recorded nowhere and counts against nothing, so once the
/// recorder is there the task's audit budget is whole.
///
/// **Canary.** Call `admit_denial_record` before the recorder check in
/// `record_seccomp_audit`: the four recorded calls are suppressed.
#[test]
fn an_audited_call_with_no_recorder_spends_nothing() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene { tid: a };
    arm_limiter();
    __seccomp_audit_recorder_clear_for_tests();
    become_user(a);

    for _ in 0..10 {
        record_seccomp_audit(999);
    }
    assert_eq!(audits_of(a), 0);
    set_seccomp_audit_recorder(audit_hook);
    for _ in 0..4 {
        record_seccomp_audit(999);
    }
    assert_eq!(audits_of(a), 4, "unrecorded audited calls spent the budget");
    set_now(WINDOW);
    cap_denial_flush_pending();
    assert!(summaries().is_empty());
    __seccomp_audit_recorder_clear_for_tests();
}

// ═════════════════════════════════════════════════════════════════════════
// One record per typed denial, under its own kind
// ═════════════════════════════════════════════════════════════════════════

/// The cap-store pool slot the typed callers below are bound to.
const SLOT: usize = 54;

/// A ring-3 caller (`ring3`, whose TID resolves in `cap_store` at `SLOT`), with
/// `SCRATCH` mapped so every handler that copies its buffer first gets as far
/// as its capability.
fn ring3_with_table(tid: u32) -> Scene {
    let s = ring3(tid);
    map_scratch();
    s
}

/// **Every typed call that resolves a capability, handed the forged handle 0,
/// writes exactly one record, under its own family's kind.**
///
/// `sys_sensor_read_typed` recorded its Sensor denial and then went through
/// `errno_for_cap_err`, which recorded it again as `DriverRegistry`: two
/// records, one of them naming a device nobody asked for. The list is every
/// non-minting entry of `CAP_TYPED_SYSCALLS`, and its length is pinned to that
/// table, so a family added later without a line here fails the count.
///
/// **Canary.** Put `note_typed_denial(CapKind::Sensor, e)` back in front of
/// the sensor mapper call: the sensor line reads two records.
#[test]
fn every_typed_call_records_one_denial_under_its_own_kind() {
    use azos_abi::cap::CapKind;
    let _g = serial();
    let tid = fresh_tid();
    let _s = ring3_with_table(tid);
    __cap_deny_limiter_clear_for_tests();
    set_cap_deny_recorder(untyped_hook);
    set_cap_deny_typed_recorder(typed_hook);
    const S: u64 = SCRATCH as u64;

    let calls: &[(&str, CapKind, fn() -> i64)] = &[
        ("chan_write", CapKind::Channel, || sys_chan_write_typed(0, S, 4)),
        ("chan_read", CapKind::Channel, || sys_chan_read_typed(0, S, 4)),
        ("port_poll", CapKind::Port, || sys_port_poll_typed(0, S)),
        ("port_destroy", CapKind::Port, || sys_port_destroy_typed(0)),
        ("port_bind", CapKind::Port, || sys_port_bind_typed(0, 2, 0, 0)),
        ("port_wait", CapKind::Port, || sys_port_wait_typed(0, S)),
        ("shm_acquire", CapKind::Shm, || sys_shm_acquire_typed(0, S)),
        ("shm_release", CapKind::Shm, || sys_shm_release_typed(0)),
        ("shm_map", CapKind::Shm, || sys_shm_map_typed(0)),
        ("ioring_submit", CapKind::IoRing, || sys_ioring_submit_typed(0)),
        ("ioring_destroy", CapKind::IoRing, || sys_ioring_destroy_typed(0)),
        ("gpio_read", CapKind::Gpio, || sys_gpio_read_typed(0)),
        ("gpio_write", CapKind::Gpio, || sys_gpio_write_typed(0, 1)),
        ("gpio_set_dir", CapKind::Gpio, || sys_gpio_set_dir_typed(0, 1)),
        ("i2c_read", CapKind::I2c, || sys_i2c_read_typed(0, 0, S, 4)),
        ("i2c_write", CapKind::I2c, || sys_i2c_write_typed(0, S, 4)),
        ("i2c_detect", CapKind::I2c, || sys_i2c_detect_typed(0)),
        ("pwm_enable", CapKind::Pwm, || sys_pwm_enable_typed(0)),
        ("pwm_disable", CapKind::Pwm, || sys_pwm_disable_typed(0)),
        ("pwm_set_period", CapKind::Pwm, || sys_pwm_set_period_typed(0, 20_000_000)),
        ("pwm_set_duty", CapKind::Pwm, || sys_pwm_set_duty_typed(0, 500)),
        ("pwm_set_duty_pct", CapKind::Pwm, || sys_pwm_set_duty_pct_typed(0, 50)),
        ("motor_set_target", CapKind::Motor, || sys_motor_set_target_typed(0, 0, 0)),
        ("motor_tick", CapKind::Motor, || sys_motor_tick_typed(0, 0, 0, 0, S)),
        ("motor_enable", CapKind::Motor, || sys_motor_enable_typed(0, 1)),
        ("motor_enabled", CapKind::Motor, || sys_motor_enabled_typed(0)),
        ("motor_set_gains", CapKind::Motor, || sys_motor_set_gains_typed(0, 1, 1, 1)),
        ("motor_reset", CapKind::Motor, || sys_motor_reset_typed(0)),
        ("motor_speed", CapKind::Motor, || sys_motor_speed_typed(0, 0)),
        ("motor_direction", CapKind::Motor, || sys_motor_direction_typed(0, 1)),
        ("motor_angle", CapKind::Motor, || sys_motor_angle_typed(0, S)),
        // 584, U11-12/W2-B4 — lives in `crate::motor_cmd`, a sibling of this
        // `mod handlers { .. }`, not inside it; every other entry here is a
        // bare name because `use super::*` (from `mod handlers`) brought it
        // in, this one needs its full path.
        ("motor_move", CapKind::Motor, || crate::motor_cmd::sys_motor_move_typed(0, 1, 0)),
        ("driver_register", CapKind::DriverRegistry, || sys_driver_register_typed(0, 0, 0, 0)),
        ("driver_unregister", CapKind::DriverRegistry, || sys_driver_unregister_typed(0)),
        ("sensor_read", CapKind::Sensor, || sys_sensor_read_typed(0, S, 64)),
        // 606, wave 11: the stamped read, through the same capability check.
        ("sensor_read_ts", CapKind::Sensor, || sys_sensor_read_ts(0, S, 64)),
        ("file_read", CapKind::File, || sys_file_read_typed(0, S, 4)),
        ("file_write", CapKind::File, || sys_file_write_typed(0, S, 4)),
        ("close", CapKind::File, || sys_close_typed(0)),
        // 600, owner round 23.
        ("fsync", CapKind::File, || sys_fsync_typed(0)),
        ("connect", CapKind::Socket, || sys_connect_typed(0, S, 16)),
        ("send", CapKind::Socket, || sys_send_typed(0, S, 4)),
        ("recv", CapKind::Socket, || sys_recv_typed(0, S, 4)),
        ("mcast_join", CapKind::Socket, || sys_mcast_join_typed(0, 0xE000_0001)),
        ("mcast_leave", CapKind::Socket, || sys_mcast_leave_typed(0, 0xE000_0001)),
        // `SYS_IPC_FAST_CALL_EP` (582, RFC-0040 gap 2). Its dispatch arm is in
        // `crates/core/syscall/src/dispatch.rs`, which this crate does not compile,
        // so the line calls the authority check the arm delegates to — which
        // is where the capability is resolved and therefore where the denial
        // is recorded. Testing the arm's `u32::try_from` shell instead would
        // prove nothing about the kind a denial lands under.
        ("ipc_fast_call_ep", CapKind::Endpoint, || {
            let t = azos_sched::current_task_tid();
            crate::handlers::endpoint_dest_recording(t, 0).map_or(-1, |v| v as i64)
        }),
        // 591, U06-9 — lives in `crate::link_key`, a sibling of this
        // `mod handlers { .. }`, not inside it, same reason `motor_move`
        // above needs its full path rather than a bare name.
        ("link_key_read", CapKind::LinkKey, || crate::link_key::sys_link_key_read_typed(0, S, 4)),
        // 595, wave 6 — `crate::vdso_notify`, a sibling like `link_key`.
        ("vdso_sensor_bind", CapKind::Sensor, || crate::vdso_notify::sys_vdso_sensor_bind(0)),
        // 596, wave 9 (P9) — `crate::entropy`, a sibling like `link_key`.
        ("entropy_read", CapKind::Entropy, || crate::entropy::sys_entropy_read_typed(0, S, 4)),

        // 602, wave 9.
        ("ipc_lease_wait", CapKind::Lease, || sys_ipc_lease_wait(0)),
        // 603 (2026-09-28): consumes a `Cap<Shm>` before it mints a `Cap<Lease>`.
        ("ipc_lease_grant_typed", CapKind::Shm, || sys_ipc_lease_grant_typed(0, 1, 0)),
        // 604, wave 11 (PORTWAIT).
        ("port_wait_until", CapKind::Port, || sys_port_wait_until_typed(0, S, 0)),
        // 614, wave 11 (RFC-0055 S5) — `crate::power`. The rate set: a WRITE.
        ("power_typed", CapKind::Power, || crate::power::sys_power_typed(0, azos_abi::power::POWER_OP_SCHED_HZ_SET, 100)),
        // 615..=618, wave 12 — `crate::families`, each one's WRITE operation.
        ("flight_typed", CapKind::Motor, || crate::families::sys_flight_typed(0, azos_abi::families::FLIGHT_OP_ARM, 0)),
        ("behavior_typed", CapKind::Power, || crate::families::sys_behavior_typed(0, azos_abi::families::BEHAVIOR_OP_DISABLE, 2)),
        ("config_typed", CapKind::Power, || crate::families::sys_config_typed(0, azos_abi::families::CONFIG_OP_SET, S, 1, S, 1)),
        ("ota_typed", CapKind::Power, || crate::families::sys_ota_typed(0, azos_abi::families::OTA_OP_ROLLBACK, 0)),
    ];
    // The SEVEN mints (530, 533, 536, 563, 567, 573, 583) resolve no
    // capability. Every other member consumes one, 574 to 578 included, so the
    // list grows with the table and the seven stays seven. 603 mints a
    // `Cap<Lease>` too, but only after it resolved the caller's `Cap<Shm>`, so
    // it has a line above (the raw-id 111 it replaced was the eighth mint).
    //
    // 583 (`SYS_ENDPOINT_CREATE_TYPED`, RFC-0040 gap 2 stage 4) joined on
    // 2026-09-21. It takes no capability and mints one into its creator, so it
    // has no denial to record and no line above — it is in
    // `CAP_TYPED_SYSCALLS` because a minter granted to a sandbox profile hands
    // it the power to create authority, which is the rule that set is for.
    // 607 (`SYS_PIPE_TYPED`, RFC-0055, wave 11) is the EIGHTH mint: it takes
    // no capability and mints two `Cap<Pipe>` ends into its caller.
    assert_eq!(
        calls.len(),
        azos_abi::syscall_nr::CAP_TYPED_SYSCALLS.len() - 8,
        "a typed syscall was added without a line in this list"
    );

    for &(name, kind, call) in calls {
        SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let _ = call();
        assert_eq!(
            seen(),
            vec![Seen::Typed { tid, kind: kind.denial_code(), reason: CapError::Stale.code() }],
            "{name}: one forged-handle denial must be exactly one record, under {kind:?}"
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════
// SYS_DRV_INVOKE: the kind-wide fallback and containment
// ═════════════════════════════════════════════════════════════════════════

/// A driver that names no resource for any op, so every call takes the
/// kind-wide fallback in `drv_invoke_authorized`. That is the real
/// `UserDriverProxy`'s answer for every op, `motor_driver`'s for
/// `MOTOR_OP_ENABLED`, `pwm_driver`'s for enable/disable/set-period, and the
/// GPIO/I2C drivers' for a payload too short to carry a pin or an address.
struct NoResourceDriver {
    m: azos_drv_api::DriverManifest,
}

impl azos_drv_api::Driver for NoResourceDriver {
    fn manifest(&self) -> &azos_drv_api::DriverManifest {
        &self.m
    }
    fn init(&self) -> Result<(), azos_drv_api::DriverError> {
        Ok(())
    }
    fn handle_request(
        &self,
        _op: u32,
        _input: &[u8],
        _output: &mut [u8],
    ) -> Result<usize, azos_drv_api::DriverError> {
        Err(azos_drv_api::DriverError::Unsupported)
    }
    fn shutdown(&self) -> Result<(), azos_drv_api::DriverError> {
        Ok(())
    }
    fn request_resource(&self, _op: u32, _input: &[u8]) -> Option<u32> {
        None
    }
}

const fn no_resource_driver(kind: u32) -> NoResourceDriver {
    NoResourceDriver {
        m: azos_drv_api::DriverManifest::new(
            kind,
            "no-resource",
            azos_drv_api::DriverIsolation::InKernel,
            azos_abi::cap::CapPerms::RW,
        ),
    }
}

static GPIO_DRV: NoResourceDriver = no_resource_driver(azos_driver_server::DRV_KIND_GPIO);
static I2C_DRV: NoResourceDriver = no_resource_driver(azos_driver_server::DRV_KIND_I2C);
static PWM_DRV: NoResourceDriver = no_resource_driver(azos_driver_server::DRV_KIND_PWM);
static MOTOR_DRV: NoResourceDriver = no_resource_driver(azos_driver_server::DRV_KIND_MOTOR_PID);

fn bridge_allows(drv: &'static NoResourceDriver, op: u32) -> bool {
    let d: &'static dyn azos_drv_api::Driver = drv;
    drv_invoke_authorized(&d, op, &[])
}

/// **The fallback is contained where the typed path is, and only there.**
///
/// While degraded, every op that writes is refused and every op that only
/// reads stays live — decided by what the op does, the same line the typed
/// family draws (`gpio_read_typed` READ, `i2c_detect_typed` READ,
/// `motor_enabled_typed` READ; every PWM op WRITE). An op number the kernel
/// does not know is refused: its effect cannot be shown to be a read.
///
/// **Canaries.** Drop the containment term from the fallback: the write ops
/// read `true` while degraded. Make `drv_op_writes` answer `true` for every op:
/// the reads go dark. Make it answer `false`: the writes go through.
#[test]
fn the_driver_bridge_fallback_is_contained_for_writes_and_live_for_reads() {
    use azos_abi::cap::CapPerms;
    use azos_ipc::cap::targets::{Gpio, I2c, Motor, Pwm};
    let _g = serial();
    let tid = fresh_tid();
    let _s = ring3_with_table(tid);

    // (driver, op, what the op does, is it a write)
    let ops: &[(&'static NoResourceDriver, u32, &str, bool)] = &[
        (&GPIO_DRV, 0, "GPIO_OP_SET_DIR", true),
        (&GPIO_DRV, 1, "GPIO_OP_READ", false),
        (&GPIO_DRV, 2, "GPIO_OP_WRITE", true),
        (&GPIO_DRV, 3, "GPIO_OP_TOGGLE", true),
        (&GPIO_DRV, 99, "unknown GPIO op", true),
        (&I2C_DRV, 0, "I2C_OP_WRITE", true),
        (&I2C_DRV, 1, "I2C_OP_READ", false),
        (&I2C_DRV, 2, "I2C_OP_DETECT", false),
        (&I2C_DRV, 99, "unknown I2C op", true),
        (&PWM_DRV, 0, "PWM_OP_ENABLE", true),
        (&PWM_DRV, 1, "PWM_OP_DISABLE", true),
        (&PWM_DRV, 2, "PWM_OP_SET_PERIOD", true),
        (&PWM_DRV, 3, "PWM_OP_SET_DUTY", true),
        (&PWM_DRV, 4, "PWM_OP_SET_DUTY_PCT", true),
        (&MOTOR_DRV, 3, "MOTOR_OP_ENABLED", false),
        (&MOTOR_DRV, 99, "unknown motor op", true),
    ];

    // Holding nothing: refused either way, so containment tells a stranger
    // nothing.
    for degraded in [false, true] {
        azos_ipc::cap::degraded_set(degraded);
        for &(drv, op, name, _) in ops {
            assert!(!bridge_allows(drv, op), "{name} allowed to a caller holding nothing (degraded={degraded})");
        }
    }

    assert!(azos_ipc::cap_store::grant::<Gpio>(tid, CapPerms::RW, 5).is_some());
    assert!(azos_ipc::cap_store::grant::<I2c>(tid, CapPerms::RW, 0x0040).is_some());
    assert!(azos_ipc::cap_store::grant::<Pwm>(tid, CapPerms::RW, 5).is_some());
    assert!(azos_ipc::cap_store::grant::<Motor>(tid, CapPerms::RW, 0).is_some());

    azos_ipc::cap::degraded_set(false);
    for &(drv, op, name, _) in ops {
        assert!(bridge_allows(drv, op), "{name} refused to a holder while not degraded");
    }

    azos_ipc::cap::degraded_set(true);
    for &(drv, op, name, writes) in ops {
        assert_eq!(
            bridge_allows(drv, op),
            !writes,
            "{name} while contained: a write must be refused and a read must stay live"
        );
    }
}

/// **Before the kernel installs the bound, nothing is suppressed.** A missing
/// hook costs the old flood, never silence.
#[test]
fn without_the_limiter_every_denial_is_recorded() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene { tid: a };
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_recorder(untyped_hook);
    __cap_deny_limiter_clear_for_tests();
    become_user(a);

    for _ in 0..20 {
        gpio_denial(7);
    }
    assert_eq!(records_of(a), 20);
}

// ═════════════════════════════════════════════════════════════════════════
// Releases: live while contained, authority unchanged
// ═════════════════════════════════════════════════════════════════════════

/// A capability minted straight into `tid`'s table, as the raw handle a
/// syscall takes.
fn held<T: azos_ipc::cap::CapTarget>(
    tid: u32,
    perms: azos_abi::cap::CapPerms,
    resource: u32,
) -> u64 {
    azos_ipc::cap_store::grant::<T>(tid, perms, resource)
        .expect("cap table full")
        .raw()
        .as_raw() as u64
}

/// **Destroying a port or an io_ring is live while contained and still needs
/// `WRITE`.** A READ-only capability is refused as before, and the port's
/// destroy revokes its capability, so a second one is stale rather than a
/// second release.
///
/// The ring half does not create a ring: it holds a `WRITE` capability naming
/// ring 3, which no test in this crate activates. Contained, `get` would answer `-EAGAIN` before the destroy;
/// resolved without the containment step, the call reaches `io_ring_destroy_ref`,
/// which answers `Stale` (`-ECAPSTALE`) because the slot does not carry the
/// capability's generation (a bare index has generation 0, RFC-0040 gap 1) —
/// and that function consults nothing about containment. The ring's submit
/// resolves without containment too (RFC-0041 §E): containment refuses each
/// write entry it executes, so on the same handle it reaches the ring and reads
/// `-ECAPSTALE`; `ioring_ops_guards.rs` asserts the per-entry refusal.
///
/// **Canaries.** Resolve `port_destroy_cap` with `get`: the contained port
/// destroy reads `-EAGAIN`. Same for `sys_ioring_destroy_typed`: the ring
/// destroy reads `-EAGAIN` instead of `-ECAPSTALE`.
#[test]
fn port_and_ioring_destroy_are_live_while_contained_and_still_need_write() {
    use azos_abi::cap::CapPerms;
    use azos_ipc::cap::targets::{IoRing, Port};
    const INACTIVE_RING: u32 = 3;
    let _g = serial();
    let tid = fresh_tid();
    let _s = ring3_with_table(tid);
    let port = sys_port_create_typed();
    assert!(port >= 0, "port create returned {port}");
    let port = port as u64;
    let ring = held::<IoRing>(tid, CapPerms::RW, INACTIVE_RING);
    let ro_port = held::<Port>(tid, CapPerms::READ, 0);
    let ro_ring = held::<IoRing>(tid, CapPerms::READ, INACTIVE_RING);

    azos_ipc::cap::degraded_set(true);
    assert_eq!(
        sys_ioring_submit_typed(ring),
        Errno::ECAPSTALE.to_syscall_ret(),
        "the submit resolves uncontained; its write entries are contained one by one"
    );
    assert_eq!(sys_port_destroy_typed(ro_port), Errno::ECAPPERMS.to_syscall_ret(), "READ-only port");
    assert_eq!(sys_ioring_destroy_typed(ro_ring), Errno::ECAPPERMS.to_syscall_ret(), "READ-only ring");
    assert_eq!(sys_port_destroy_typed(port), 0, "port destroy while contained");
    assert_eq!(sys_port_destroy_typed(port), Errno::ECAPSTALE.to_syscall_ret(), "second port destroy");
    assert_eq!(
        sys_ioring_destroy_typed(ring),
        Errno::ECAPSTALE.to_syscall_ret(),
        "the contained ring destroy did not reach io_ring_destroy"
    );
}

// ═════════════════════════════════════════════════════════════════════════
// Motors under e-stop and containment: stopping yes, changing direction no
// ═════════════════════════════════════════════════════════════════════════
//
// These drive the real `domains/robot/robot/src/motor.rs` (see `shims/robot`). The
// halt query and gate installed here read the test's e-stop latch together
// with `degraded_active()`, the two conditions the kernel's `actuation_halt`
// and `actuation_gate` answer on; that kernel wiring is covered by the kernel
// build, not by this crate.

static ESTOP: AtomicBool = AtomicBool::new(false);

fn test_halt() -> bool {
    ESTOP.load(Ordering::SeqCst) || azos_ipc::cap::degraded_active()
}

/// The kernel's gate answers 0 for a latched e-stop and at the CONTAINED
/// degrade level (speed cap 0 %), and passes the request otherwise.
fn test_gate(_id: u32, speed_pct: u32) -> u32 {
    if test_halt() { 0 } else { speed_pct }
}

/// A gate that allows everything, to show the halt zeroes the duty alone.
fn open_gate(_id: u32, speed_pct: u32) -> u32 {
    speed_pct
}

static PWM_CALLS: Mutex<Vec<(PwmOp, u32, u32)>> = Mutex::new(Vec::new());

/// Records the call; a duty write reports the percentage it was given as the
/// applied one, which is what the real simulated channel does.
fn pwm_probe(op: PwmOp, ch: u32, arg: u32) -> i32 {
    PWM_CALLS.lock().unwrap_or_else(|e| e.into_inner()).push((op, ch, arg));
    if op == PwmOp::SetDutyPct { arg as i32 } else { 0 }
}

fn pwm_calls() -> Vec<(PwmOp, u32, u32)> {
    PWM_CALLS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn clear_probes() {
    GPIO_CALLS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    PWM_CALLS.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

const WHEEL: u32 = 0;
const WHEEL_CH: u32 = 4;
const PIN_A: u32 = 20;
const PIN_B: u32 = 21;

/// Install the hooks and both probes, initialise `WHEEL`, and empty the probe
/// logs of the initialisation.
fn wheel() {
    azos_robot::motor::set_motor_halt(test_halt);
    azos_robot::motor::set_motor_gate(test_gate);
    install_gpio_probe();
    set_pwm_probe(Some(pwm_probe));
    assert_eq!(azos_robot::motor_init(WHEEL, WHEEL_CH, PIN_A, PIN_B), 0);
    clear_probes();
}

#[derive(Clone, Copy, Debug)]
enum Halt {
    Estop,
    Contained,
}

fn arm(h: Halt) {
    match h {
        Halt::Estop => ESTOP.store(true, Ordering::SeqCst),
        Halt::Contained => azos_ipc::cap::degraded_set(true),
    }
}

fn disarm() {
    ESTOP.store(false, Ordering::SeqCst);
    azos_ipc::cap::degraded_set(false);
}

fn pins(a: u32, b: u32) -> Vec<(GpioOp, u32, u32)> {
    vec![(GpioOp::Write, PIN_A, a), (GpioOp::Write, PIN_B, b)]
}

fn duty(pct: u32) -> Vec<(PwmOp, u32, u32)> {
    vec![(PwmOp::SetDutyPct, WHEEL_CH, pct)]
}

fn recorded(dir: azos_robot::MotorDir, speed: u32) -> bool {
    matches!(azos_robot::motor_state(WHEEL), Some((d, s)) if d == dir && s == speed)
}

/// **The kernel's own writes are held to the same rule.** A kernel-context
/// forward or backward — `rt_motor_task` asks `Forward` at 0 % every tick
/// under an e-stop — is refused without touching the pins, reports duty 0 so
/// the control loop's readback still reads 0, and leaves the recorded
/// direction alone.
///
/// **Canary.** Delete the refusal branch in `motor_set_reporting`: the call
/// returns `(0, Some(0))` and the probe sees the pins.
#[test]
fn a_kernel_direction_change_is_refused_while_halted() {
    use azos_robot::MotorDir::{Backward, Coast, Forward};
    for cause in [Halt::Estop, Halt::Contained] {
        let _g = serial();
        let _s = Scene { tid: 0 };
        wheel();
        arm(cause);
        for (dir, ask) in [(Forward, 0), (Forward, 60), (Backward, 60)] {
            clear_probes();
            assert_eq!(
                motor_set_reporting(WHEEL, dir, ask),
                (azos_robot::MOTOR_REFUSED_HALTED, Some(0)),
                "{cause:?}: ask {ask}"
            );
            assert!(gpio_calls().is_empty(), "{cause:?}: the pins were written: {:?}", gpio_calls());
            assert_eq!(pwm_calls(), duty(0), "{cause:?}");
        }
        assert!(recorded(Coast, 0), "{cause:?}: motor_init records Coast, and nothing since was applied");
    }
}

/// **The typed speed call gives the halt rule's answer.** On the same wheel,
/// while halted: a forward is `-EAGAIN` with the pins untouched and duty 0
/// written, and a stop is carried out — while contained too, where
/// `CapTable::get` would refuse it. Authority is unchanged: a READ-only
/// capability is still refused for the stop.
///
/// **Canaries.** Resolve `motor_speed_cap_id` with `get`: the contained typed
/// stop reads `-EAGAIN`. Return `rc as i64` from `sys_motor_speed_typed`: the
/// typed forward reads `-2`. Delete the refusal branch in
/// `motor_set_reporting`: the probe sees the pins.
#[test]
fn the_typed_speed_call_gives_the_halt_rules_answer_while_halted() {
    use azos_abi::cap::CapPerms;
    use azos_ipc::cap::targets::Motor;
    for cause in [Halt::Estop, Halt::Contained] {
        let _g = serial();
        let tid = fresh_tid();
        let _s = ring3_with_table(tid);
        let cap = held::<Motor>(tid, CapPerms::RW, WHEEL);
        let read_only = held::<Motor>(tid, CapPerms::READ, WHEEL);
        wheel();
        arm(cause);

        assert_eq!(sys_motor_speed_typed(cap, 60), eagain(), "{cause:?}: typed forward");
        assert!(gpio_calls().is_empty(), "{cause:?}: the pins were written: {:?}", gpio_calls());
        assert_eq!(pwm_calls(), duty(0), "{cause:?}: a refused forward writes duty 0");

        clear_probes();
        assert_eq!(sys_motor_speed_typed(cap, 0), 0, "{cause:?}: typed stop");
        assert_eq!(gpio_calls(), pins(0, 0), "{cause:?}");

        assert_eq!(
            sys_motor_speed_typed(read_only, 0),
            Errno::ECAPPERMS.to_syscall_ret(),
            "{cause:?}: a READ-only capability stopped a wheel"
        );
    }
}

/// **The PID calls stay contained, disabling the loop included.** None of them
/// leaves a wheel stopped: `motor_pid_enable(false)` only clears `PID_ENABLED`,
/// after which `rt_motor_task` applies the motor command open-loop, and a zero
/// target or a reset is overwritten by that loop's next tick. The READ stays
/// live, and the same caller is admitted once cleared.
///
/// **Canary.** Resolve `require_pair_write` with `get_uncontained`: the
/// contained disable reads 0.
#[test]
fn the_pid_calls_stay_contained_disable_included() {
    use azos_abi::cap::CapPerms;
    use azos_ipc::cap::targets::Motor;
    let _g = serial();
    let tid = fresh_tid();
    let _s = ring3_with_table(tid);
    let cap = held::<Motor>(tid, CapPerms::RW, 0);
    let _right = held::<Motor>(tid, CapPerms::RW, 1);

    azos_ipc::cap::degraded_set(true);
    assert_eq!(sys_motor_enable_typed(cap, 0), eagain(), "disable");
    assert_eq!(sys_motor_enable_typed(cap, 1), eagain(), "enable");
    assert_eq!(sys_motor_set_target_typed(cap, 0, 0), eagain(), "zero target");
    assert_eq!(sys_motor_reset_typed(cap), eagain(), "reset");
    assert_eq!(sys_motor_set_gains_typed(cap, 1, 1, 1), eagain(), "gains");
    assert_eq!(sys_motor_tick_typed(cap, 0, 0, 0, SCRATCH as u64), eagain(), "tick");
    assert!(sys_motor_enabled_typed(cap) >= 0, "the READ went dark while contained");

    azos_ipc::cap::degraded_set(false);
    assert_eq!(sys_motor_enable_typed(cap, 1), 0, "the pair holder was refused once cleared");
}

/// **Ring 3 does not bind a motor, whatever it holds.** A caller holding
/// `Motor`, `Pwm` and both `Gpio` capabilities is refused with `E_PERM`,
/// contained or not, and the drivers see nothing: rebinding a motor would move
/// the motor-bound guards off its channel and pins. Each refusal writes the
/// one record every ring-3 call of this handler wrote under the handle table,
/// which never held a PWM entry for ring 3: the PWM channel, write bit set. A
/// caller not holding the motor keeps that refusal. A kernel caller binds.
///
/// **Canaries.** Delete the ring-3 refusal in `sys_motor_create`: the
/// uncontained call reads 0 and the probes see `motor_init`. Record `Gpio`
/// instead of `Pwm`: the record line reads kind 2.
#[test]
fn motor_create_is_refused_to_ring3_whatever_it_holds() {
    let _g = serial();
    let s = ring3(fresh_tid());
    hold(s.tid, CapKind::Motor, 2, CapPerms::RW);
    hold(s.tid, CapKind::Pwm, 6, CapPerms::RW);
    hold(s.tid, CapKind::Gpio, 24, CapPerms::RW);
    hold(s.tid, CapKind::Gpio, 25, CapPerms::RW);
    install_gpio_probe();
    set_pwm_probe(Some(pwm_probe));
    clear_probes();
    __cap_deny_limiter_clear_for_tests();
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_recorder(untyped_hook);

    for degraded in [true, false] {
        azos_ipc::cap::degraded_set(degraded);
        assert_eq!(sys_motor_create(2, 6, 24, 25), E_PERM, "motor_create from ring 3, degraded={degraded}");
    }
    assert!(gpio_calls().is_empty(), "the GPIO driver saw {:?}", gpio_calls());
    assert!(pwm_calls().is_empty(), "the PWM driver saw {:?}", pwm_calls());
    let pwm_write = Seen::Untyped { tid: s.tid, kind: CapKind::Pwm.denial_code(), detail: 6 | 0x8000_0000 };
    assert_eq!(seen(), vec![pwm_write, pwm_write]);

    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    assert_eq!(sys_motor_create(3, 6, 24, 25), E_PERM, "an unheld motor");
    assert_eq!(
        seen(),
        vec![Seen::Untyped { tid: s.tid, kind: CapKind::Motor.denial_code(), detail: 3 | 0x8000_0000 }]
    );

    azos_sched::set_current_user_pt(0);
    assert_eq!(sys_motor_create(2, 6, 24, 25), 0, "a kernel caller");
    assert_eq!(gpio_calls(), vec![(GpioOp::SetDirection, 24, 1), (GpioOp::SetDirection, 25, 1)]);
    assert_eq!(
        pwm_calls(),
        vec![(PwmOp::SetPeriod, 6, 1_000_000), (PwmOp::Enable, 6, 0), (PwmOp::SetDutyPct, 6, 0)]
    );
}

// ═════════════════════════════════════════════════════════════════════════
// SYS_MOTOR_DIRECTION_TYPED (576): 231's body behind a Cap<Motor>
// ═════════════════════════════════════════════════════════════════════════

/// **576 applies the halt rule.** For both causes: after a brake while not
/// halted, a typed forward and reverse answer `-EAGAIN` without touching the
/// pins, each writing duty 0, and the motor table still records the brake; a
/// typed coast and a typed brake are carried out at duty 0; a kernel-context
/// brake asking 80 % through a gate that allows everything still lands at duty
/// 0; once cleared the typed reverse writes the pins at duty 50. The capability
/// names one wheel and is enough: no pair rule.
///
/// **Canaries.** Resolve 576 with `get(cap, WRITE)`: the contained coast reads
/// `-EAGAIN`. Return `rc as i64` from `motor_direction_reporting`: the forward
/// reads the motor layer's code. Delete the refusal branch in
/// `motor_set_reporting`: the probe sees the pins. Refuse every direction while
/// halted: the brake reads `-EAGAIN`. Take the duty from the gate while halted:
/// the kernel brake reports 80.
#[test]
fn the_typed_direction_call_gives_231s_answer_while_halted() {
    use azos_ipc::cap::targets::Motor;
    use azos_robot::MotorDir::{Backward, Brake, Coast};
    for cause in [Halt::Estop, Halt::Contained] {
        let _g = serial();
        let tid = fresh_tid();
        let _s = ring3_with_table(tid);
        let cap = held::<Motor>(tid, CapPerms::RW, WHEEL);
        wheel();
        assert_eq!(sys_motor_direction_typed(cap, 2), 0, "{cause:?}: brake before halting");
        clear_probes();

        arm(cause);
        assert_eq!(sys_motor_direction_typed(cap, 0), eagain(), "{cause:?}: typed forward");
        assert_eq!(sys_motor_direction_typed(cap, 1), eagain(), "{cause:?}: typed reverse");
        assert!(gpio_calls().is_empty(), "{cause:?}: the pins were written: {:?}", gpio_calls());
        assert_eq!(pwm_calls(), [duty(0), duty(0)].concat(), "{cause:?}");
        assert!(recorded(Brake, 0), "{cause:?}: the table records a direction that was not applied");

        clear_probes();
        assert_eq!(sys_motor_direction_typed(cap, 3), 0, "{cause:?}: typed coast while halted");
        assert_eq!(gpio_calls(), pins(0, 0), "{cause:?}");
        assert_eq!(pwm_calls(), duty(0), "{cause:?}");
        assert!(recorded(Coast, 0), "{cause:?}");

        clear_probes();
        assert_eq!(sys_motor_direction_typed(cap, 2), 0, "{cause:?}: typed brake while halted");
        assert_eq!(gpio_calls(), pins(1, 1), "{cause:?}");
        assert_eq!(pwm_calls(), duty(0), "{cause:?}");
        assert!(recorded(Brake, 0), "{cause:?}");

        let user_pt = azos_sched::current_user_pt();
        azos_robot::motor::set_motor_gate(open_gate);
        azos_sched::set_current_user_pt(0);
        clear_probes();
        assert_eq!(motor_set_reporting(WHEEL, Brake, 80), (0, Some(0)), "{cause:?}: kernel brake");
        assert_eq!(gpio_calls(), pins(1, 1), "{cause:?}");
        azos_robot::motor::set_motor_gate(test_gate);
        azos_sched::set_current_user_pt(user_pt);

        disarm();
        clear_probes();
        assert_eq!(sys_motor_direction_typed(cap, 1), 0, "{cause:?}: typed reverse once cleared");
        assert_eq!(gpio_calls(), pins(0, 1), "{cause:?}");
        assert_eq!(pwm_calls(), duty(50), "{cause:?}");
        assert!(recorded(Backward, 50), "{cause:?}");
    }
}

/// **576 takes its wheel from the capability and needs `WRITE`.** A READ-only
/// capability, a capability of another kind and the forged handle are refused
/// with their errno and one typed record each, and none reaches a wheel. A
/// capability for another initialised wheel drives that wheel and not `WHEEL`:
/// there is no id argument to disagree with it.
///
/// **Canaries.** Resolve with `READ` instead of `WRITE`: the READ-only line
/// reads 0 and the probes see `WHEEL`. Command wheel 0 whatever the
/// capability names: the other-wheel line writes `WHEEL`'s pins.
#[test]
fn the_typed_direction_call_takes_its_wheel_from_the_capability_and_needs_write() {
    use azos_ipc::cap::targets::{Gpio, Motor};
    const OTHER: u32 = 3;
    const OTHER_CH: u32 = 7;
    const OTHER_A: u32 = 26;
    const OTHER_B: u32 = 27;
    let _g = serial();
    let tid = fresh_tid();
    let _s = ring3_with_table(tid);
    wheel();
    assert_eq!(azos_robot::motor_init(OTHER, OTHER_CH, OTHER_A, OTHER_B), 0);
    clear_probes();
    __cap_deny_limiter_clear_for_tests();
    set_cap_deny_typed_recorder(typed_hook);
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    let read_only = held::<Motor>(tid, CapPerms::READ, WHEEL);
    let gpio = held::<Gpio>(tid, CapPerms::RW, PIN_A);
    let other = held::<Motor>(tid, CapPerms::RW, OTHER);

    assert_eq!(sys_motor_direction_typed(read_only, 1), Errno::ECAPPERMS.to_syscall_ret(), "READ-only");
    assert_eq!(sys_motor_direction_typed(gpio, 1), Errno::ECAPKIND.to_syscall_ret(), "a Gpio capability");
    assert_eq!(sys_motor_direction_typed(0, 1), Errno::ECAPSTALE.to_syscall_ret(), "the forged handle");
    assert!(
        gpio_calls().is_empty() && pwm_calls().is_empty(),
        "a refused call reached a wheel: {:?} {:?}",
        gpio_calls(),
        pwm_calls()
    );
    let motor = CapKind::Motor.denial_code();
    assert_eq!(
        seen(),
        vec![
            Seen::Typed { tid, kind: motor, reason: CapError::MissingPerms.code() },
            Seen::Typed { tid, kind: motor, reason: CapError::WrongKind.code() },
            Seen::Typed { tid, kind: motor, reason: CapError::Stale.code() },
        ]
    );

    assert_eq!(sys_motor_direction_typed(other, 1), 0, "the other wheel");
    assert_eq!(gpio_calls(), vec![(GpioOp::Write, OTHER_A, 0), (GpioOp::Write, OTHER_B, 1)]);
    assert_eq!(pwm_calls(), vec![(PwmOp::SetDutyPct, OTHER_CH, 50)]);
}

/// **576 refuses a direction past coast, after the capability and before the
/// motor layer** (owner decision, gap 1 Q5). A holder of a WRITE capability
/// asking 4, 5 or `u64::MAX` gets `-EINVAL` — from the direction, since the
/// capability resolves — with no pin written, no duty written, no record and
/// the motor table unchanged; 3 still coasts. The `[ACTSMOKE]` marker is
/// printed below the refusal and this crate does not build `actuation-smoke`,
/// so the probes stand for it. A refused capability keeps its own errno ahead
/// of the direction.
///
/// **Canary.** Map any other value to coast in `motor_direction_reporting`
/// (`_ => MotorDir::Coast`): the dir=4 line reads 0 and the probes see the pins.
#[test]
fn the_typed_direction_call_refuses_a_direction_past_coast_before_the_motor_layer() {
    use azos_ipc::cap::targets::Motor;
    use azos_robot::MotorDir::Coast;
    let _g = serial();
    let tid = fresh_tid();
    let _s = ring3_with_table(tid);
    let cap = held::<Motor>(tid, CapPerms::RW, WHEEL);
    let read_only = held::<Motor>(tid, CapPerms::READ, WHEEL);
    wheel();
    assert_eq!(sys_motor_direction_typed(cap, 2), 0, "precondition: a brake");
    let before = azos_robot::motor_state(WHEEL);
    clear_probes();
    __cap_deny_limiter_clear_for_tests();
    set_cap_deny_recorder(untyped_hook);
    set_cap_deny_typed_recorder(typed_hook);
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();

    let einval = Errno::EINVAL.to_syscall_ret();
    for dir in [4u64, 5, u64::MAX] {
        assert_eq!(sys_motor_direction_typed(cap, dir), einval, "direction {dir}");
    }
    assert!(
        gpio_calls().is_empty() && pwm_calls().is_empty(),
        "a refused direction reached the wheel: {:?} {:?}",
        gpio_calls(),
        pwm_calls()
    );
    assert!(azos_robot::motor_state(WHEEL) == before, "a refused direction changed the motor table");
    assert!(seen().is_empty(), "a refused direction wrote a record: {:?}", seen());

    assert_eq!(
        sys_motor_direction_typed(read_only, 4),
        Errno::ECAPPERMS.to_syscall_ret(),
        "the capability is resolved before the direction"
    );
    assert_eq!(seen().len(), 1, "a refused capability writes its one record: {:?}", seen());

    assert_eq!(sys_motor_direction_typed(cap, 3), 0, "direction 3 still coasts");
    assert_eq!(gpio_calls(), pins(0, 0));
    assert!(matches!(azos_robot::motor_state(WHEEL), Some((d, _)) if d == Coast));
}

// ═════════════════════════════════════════════════════════════════════════
// SYS_ROBOT_ESTOP: authority from the capability table, never contained
// ═════════════════════════════════════════════════════════════════════════

static ESTOPS: AtomicU32 = AtomicU32::new(0);

fn count_estop() {
    ESTOPS.fetch_add(1, Ordering::SeqCst);
}

/// **A ring-3 e-stop from a holder of WRITE on any motor is carried out while
/// contained.** Containment is armed when something has gone wrong, which is
/// when a stop is issued; refusing it there would leave a program that may
/// drive unable to stop. Holding nothing, or READ on both wheels, is one
/// refusal and one record per call, and no stop. A kernel caller needs no
/// table.
///
/// **Canaries.** Swap `holds_kind_with(Motor, WRITE)` for
/// `(0..MAX_MOTORS).any(|id| holds_kind_resource_with(Motor, id, WRITE))`: the
/// contained stop reads `E_PERM`. Ask `READ`: the READ line reads 0.
#[test]
fn a_ring3_estop_is_carried_out_while_contained() {
    let _g = serial();
    let tid = fresh_tid();
    let _s = ring3(tid);
    __cap_deny_limiter_clear_for_tests();
    set_cap_deny_recorder(untyped_hook);
    set_estop_handler(count_estop);
    ESTOPS.store(0, Ordering::SeqCst);
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    let refusal = Seen::Untyped { tid, kind: CapKind::Motor.denial_code(), detail: 0x8000_0000 };

    assert_eq!(sys_robot_estop(), E_PERM, "a caller holding nothing");
    hold(tid, CapKind::Motor, 0, CapPerms::READ);
    hold(tid, CapKind::Motor, 1, CapPerms::READ);
    assert_eq!(sys_robot_estop(), E_PERM, "a caller holding READ on both wheels");
    assert_eq!(seen(), vec![refusal, refusal], "one record per refused call");
    assert_eq!(ESTOPS.load(Ordering::SeqCst), 0, "a refused e-stop was carried out");

    hold(tid, CapKind::Motor, 1, CapPerms::WRITE);
    azos_ipc::cap::degraded_set(true);
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    assert_eq!(sys_robot_estop(), 0, "the holder's e-stop was refused while contained");
    assert_eq!(ESTOPS.load(Ordering::SeqCst), 1);
    assert!(seen().is_empty(), "an e-stop that was carried out wrote a denial: {:?}", seen());

    azos_sched::set_current_user_pt(0);
    azos_sched::set_current_task_tid(0);
    assert_eq!(sys_robot_estop(), 0, "a kernel caller");
    assert_eq!(ESTOPS.load(Ordering::SeqCst), 2);
}

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
// | GPIO/I2C/PWM writes              | none (200-213, 221 retired)         | device_guards.rs |
// | CHAN_WRITE_TYPED 528             | none (101, 507 retired)             | typed_ipc.rs    |
// | DRIVER_REGISTER_TYPED 556        | none (520 retired)                  | contained       |
// | IORING_SUBMIT_TYPED 537          | none (504 retired)                  | —               |
// | MOTOR_SET_TARGET/TICK/ENABLE/    | none — a disjoint surface           | —               |
// |   SET_GAINS/RESET_TYPED 550-555  |                                     |                 |
// | MCAST_JOIN_TYPED 571             | SYS_MCAST_JOIN is a stub            | —               |
//
// Deliberately live: fd 1/2 (the console), every receive, every close, and every kernel-context caller.
//
// ── Releases and motors (owner decisions, 2026-09-13) ─────────────────────
//
// Releasing an object is exempt from containment and keeps its authority:
//
// | typed (release)                  | untyped twin                        | while contained |
// |----------------------------------|-------------------------------------|-----------------|
// | PORT_DESTROY_TYPED 532 (WRITE)   | none (514 retired)                  | live            |
// | IORING_DESTROY_TYPED 538 (WRITE) | none                                | live            |
// | DRIVER_UNREGISTER_TYPED 557 (W)  | none (521 retired)                  | live            |
// | SHM_RELEASE_TYPED 535 (READ)     | none                                | live, unchanged |
// | CLOSE_TYPED 564, MCAST_LEAVE 572 | sys_close, sys_sock_close           | live, unchanged |
// | CLOSE_TYPED 566 on a Channel (W) | none (107 retired)                  | live            |
//
// Motors: the `Motor` interface's tests are `motor_guards.rs`.
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
// `cap_check` and `errno_for_cap_err` against a hand-driven clock and read
// back, in order, everything the three hooks saw.

use super::harness::serial;
use crate::ipc_handlers::*;
use azos_abi::error::Errno;
use azos_arch_api::PagePerms;
use azos_drv_gpio::gpio::{set_gpio_probe, GpioOp};
use azos_drv_actuator::pwm::{set_pwm_probe, PwmOp};
use azos_ipc::cap::CapError;
use azos_abi::cap::{CapKind, CapPerms, ty, CapType};
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
fn hold(tid: u32, kind: CapType, resource: u32, perms: CapPerms) {
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
    fn open_at(&self, _root: &[u8], _path: &[u8], _flags: u32) -> i64 { -1 }
    fn close(&self, _fd: i32) -> i64 { -1 }
    fn read(&self, _fd: i32, _dst: &mut [u8]) -> i64 { -1 }
    fn write(&self, fd: i32, src: &[u8]) -> i64 {
        WRITES.lock().unwrap_or_else(|e| e.into_inner()).push((fd, src.len()));
        src.len() as i64
    }
    fn lseek(&self, _fd: i32, _offset: i64, _whence: i32) -> i64 { -1 }
    fn dup(&self, _fd: i32) -> i64 { -1 }
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
/// from an unmapped address fails with `-1`. Receive stays live.
///
/// **Canary.** Delete the check from any one of the three handlers: its
/// assertion reads `-1`.
#[test]
fn socket_writes_are_contained_and_receive_stays_live() {
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

/// A driver-registry capability registers through a mask that lists `DRIVER`
/// (`DOMAIN_DRIVER_REGISTER` and `DOMAIN_DRIVER_UNREGISTER` are ops of that
/// class) and is refused by one that does not, and a refused call neither
/// claims nor releases the kind.
///
/// **Canary.** Resolve `drvreg_kind_of` with `get` (no op): the `DRIVER` copy's
/// register reads `-ECAPPERMS`.
#[test]
fn an_op_mask_gates_the_driver_registry_ops() {
    use super::harness::{classes, op_masked};
    use azos_abi::cap::CapPerms;
    use azos_abi::invoke::{CLASS_DRIVER, CLASS_READ};
    use azos_ipc::cap::targets::DriverRegistry;
    let _g = serial();
    let tid = fresh_tid();
    let _s = ring3_with_table(tid);
    let cap = held::<DriverRegistry>(tid, CapPerms::RW, DRV_KIND_TYPED);
    let (drv, rd) = (op_masked(tid, cap, classes(&[CLASS_DRIVER])), op_masked(tid, cap, classes(&[CLASS_READ])));
    let denied = Errno::ECAPPERMS.to_syscall_ret();

    assert_eq!(sys_driver_register_typed(rd, 0, 0, 0), denied);
    assert_eq!(sys_driver_register_typed(drv, 0, 0, 0), 0, "the DRIVER copy claims the kind");
    assert_eq!(sys_driver_unregister_typed(rd), denied);
    assert_eq!(sys_driver_unregister_typed(drv), 0);
    assert_eq!(sys_driver_register_typed(cap, 0, 0, 0), 0, "the DRIVER copy's unregister released the kind");
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

/// An untyped denial of a write. The kind is a stand-in: any kind has the
/// same budget arithmetic, and `Endpoint` is the one every kernel-hosted
/// interface refuses under.
fn gpio_denial(pin: u32) {
    assert!(!cap_check(ty::ENDPOINT, pin, true), "the caller was not denied");
}

fn typed_gpio_denial() {
    let _ = errno_for_cap_err(ty::ENDPOINT, CapError::Stale);
}

/// The recorder code of `ty::ENDPOINT`.
const GPIO: u8 = ty::ENDPOINT.denial_code();

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

/// **The gate's readback.** `captest` produces one untyped and one typed
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

    typed_gpio_denial(); // suppressed, endpoint
    assert!(!cap_check(ty::IRQ, 1, true)); // suppressed, irq
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
        assert_eq!(errno_for_cap_err(ty::ENDPOINT, CapError::Contained), eagain());
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

/// **The gate-40 shape.** `captest` makes 12 capability denial admits (one
/// untyped, eleven typed; `userspace/tests/captest/src/main.rs`) in one window before
/// it issues syscall 116 under its audit profile. The audit record of 116 must
/// still be written, and so must a ring-3 exec refusal after it: a capability
/// flood cannot silence the other classes. Its own denials are still cut at four.
///
/// Every capability kind shares class 0, so the budget arithmetic is the same
/// whichever kind a refusal is recorded under.
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

    gpio_denial(9); // one more untyped admit
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
    assert_eq!(summaries(), vec![(GPIO, 8)], "only the capability class suppressed anything");
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
/// The typed sensor read once recorded its denial and then went through
/// `errno_for_cap_err`, which recorded it again as `DriverRegistry`: two
/// records, one of them naming a device nobody asked for. The list is every
/// non-minting entry of `CAP_TYPED_SYSCALLS`, and its length is pinned to that
/// table, so a family added later without a line here fails the count.
///
/// **Canary.** Record a denial in front of a mapper call that records its own:
/// that line reads two records.
#[test]
fn every_typed_call_records_one_denial_under_its_own_kind() {
    use azos_abi::cap::{ty, CapType};
    let _g = serial();
    let tid = fresh_tid();
    let _s = ring3_with_table(tid);
    __cap_deny_limiter_clear_for_tests();
    set_cap_deny_recorder(untyped_hook);
    set_cap_deny_typed_recorder(typed_hook);
    const S: u64 = SCRATCH as u64;

    let calls: &[(&str, CapType, fn() -> i64)] = &[
        ("port_poll", ty::PORT, || sys_port_poll_typed(0, S)),
        ("port_destroy", ty::PORT, || sys_port_destroy_typed(0)),
        ("port_bind", ty::PORT, || sys_port_bind_typed(0, 2, 0, 0)),
        ("shm_acquire", ty::SHM, || sys_shm_acquire_typed(0, S)),
        ("memobj_release", ty::SHM, || sys_shm_release_typed(0)),
        ("shm_map", ty::SHM, || sys_shm_map_typed(0, 0)),
        ("ioring_submit", ty::IORING, || sys_ioring_submit_typed(0)),
        ("ioring_destroy", ty::IORING, || sys_ioring_destroy_typed(0)),
        ("driver_register", ty::DRIVER_REGISTRY, || sys_driver_register_typed(0, 0, 0, 0)),
        ("driver_unregister", ty::DRIVER_REGISTRY, || sys_driver_unregister_typed(0)),
        ("file_read", ty::FILE, || sys_file_read_typed(0, S, 4)),
        ("file_write", ty::FILE, || sys_file_write_typed(0, S, 4)),
        ("close", ty::FILE, || sys_close_typed(0)),
        // 600, owner round 23.
        ("fsync", ty::FILE, || sys_fsync_typed(0)),
        ("connect", ty::SOCKET, || sys_connect_typed(0, S, 16)),
        ("send", ty::SOCKET, || sys_send_typed(0, S, 4)),
        ("recv", ty::SOCKET, || sys_recv_typed(0, S, 4)),
        ("mcast_join", ty::SOCKET, || sys_mcast_join_typed(0, 0xE000_0001)),
        ("mcast_leave", ty::SOCKET, || sys_mcast_leave_typed(0, 0xE000_0001)),
        // `SYS_IPC_FAST_CALL_EP` (582). Its dispatch arm is in
        // `crates/core/syscall/src/dispatch.rs`, which this crate does not compile,
        // so the line calls the authority check the arm delegates to — which
        // is where the capability is resolved and therefore where the denial
        // is recorded. Testing the arm's `u32::try_from` shell instead would
        // prove nothing about the kind a denial lands under.
        ("ipc_fast_call_ep", ty::ENDPOINT, || {
            let t = azos_sched::current_task_tid();
            crate::handlers::endpoint_dest_recording(t, 0).map_or(-1, |v| v.owner as i64)
        }),
        // 604, wave 11 (PORTWAIT).
        ("port_wait", ty::PORT, || sys_port_wait(0, S, 0)),
        // 633, wave 15 N11b: `SYS_IPC_CALL_V2` resolves its endpoint through
        // the same check as 582 (`crate::ipc_v2`, not compiled here).
        ("ipc_call_v2", ty::ENDPOINT, || {
            let t = azos_sched::current_task_tid();
            crate::handlers::endpoint_dest_recording(t, 0).map_or(-1, |v| v.owner as i64)
        }),
        // 637, wave 15 N11b: the badged mint consumes the endpoint
        // capability it copies; its arm delegates the step to this.
        ("cap_mint_badged", ty::ENDPOINT, || {
            let t = azos_sched::current_task_tid();
            crate::handlers::mint_badged_recording(t, 0, 1, azos_abi::cap::CapPerms::WRITE, 0).map_or(-1, |h| h.0 as i64)
        }),
        // 638, wave 15 N6b: `SYS_SCHEDCTL` checks the time warrant for RT
        // and DL through this step (`crate::schedctl`, not compiled here).
        ("schedctl", ty::ENDPOINT, || {
            let t = azos_sched::current_task_tid();
            crate::handlers::time_warrant_recording(t, 0).map_or(-1, |()| 0)
        }),
    ];
    // The FOUR mints (533, 536, 563, 567) resolve no capability. Every
    // other member consumes one, so the list grows with the table and the four
    // stay four. The domain's creation ops
    // (a port, an endpoint, a pipe) are ops of `invoke` on the caller's own
    // domain, no members of the typed set.
    // The ops of `invoke` and the handle calls that resolve a capability of the
    // table keep a line here though they are no member of the typed set: a
    // port's poll, bind and destroy; a memory object's acquire; a file's and a socket's node ops (read, write, fsync,
    // connect, send, recv, multicast); `SYS_CAP_CLOSE`; the derive.
    const INVOKE_OPS_IN_THIS_LIST: usize = 19;
    assert_eq!(
        calls.len(),
        azos_abi::syscall_nr::CAP_TYPED_SYSCALLS.len() - 4 + INVOKE_OPS_IN_THIS_LIST,
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

    // The tracer's ops are ops of `invoke` on a `Log` handle, no call of their
    // own (`crate::trace_ctl`): the same check, the same record. The mask set:
    // a WRITE.
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    let _ = crate::trace_ctl::trace_op(0, azos_abi::invoke::LOG_TRACE_SET_MASK, 1);
    assert_eq!(
        seen(),
        vec![Seen::Typed { tid, kind: ty::TRACE.denial_code(), reason: CapError::Stale.code() }],
        "trace ctl: one forged-handle denial must be exactly one record, under the tracer"
    );
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
/// capability's generation (a bare index has generation 0) —
/// and that function consults nothing about containment. The ring's submit
/// resolves without containment too: containment refuses each
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

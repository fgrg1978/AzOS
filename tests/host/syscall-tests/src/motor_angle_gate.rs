// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// `sys_motor_angle_typed` (SYS_MOTOR_ANGLE_TYPED, 578) reads the wheel
// encoders only for a caller holding a `Cap<Motor>` with READ, and reads the
// wheel that capability names. It replaced `SYS_MOTOR_ANGLE` (233), retired in
// RFC-0040 gap 1 with its tests.
//
// **Both halves, against the same stand-in.** `shims/robot`'s encoder is a
// pair the test sets and a read counter, so a refusal is asserted not to have
// read the encoders at all, and an admission is asserted to return exactly the
// wheel it named. A suite of refusals alone would pass against a handler that
// refuses everything.

use super::harness::serial;
use azos_abi::cap::{CapKind, CapPerms};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

/// The cap-store pool slot the caller is bound to. 22 and 51-56 are taken by
/// other files in this crate.
const SLOT: usize = 57;
/// What the encoder stand-in reports for each wheel. Distinct, and one of them
/// negative, so a wrong wheel or a sign slip cannot pass.
const LEFT: i64 = 1234;
const RIGHT: i64 = -5678;

/// TIDs no other file in this crate uses.
static NEXT_TID: AtomicU32 = AtomicU32::new(0x7a0d_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

/// Every untyped denial the recorder saw: (kind code, target, need_write).
static SEEN: Mutex<Vec<(u8, u32, bool)>> = Mutex::new(Vec::new());

fn recorder(kind_code: u8, target: u32, need_write: bool) {
    SEEN.lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((kind_code, target, need_write));
}

fn seen() -> Vec<(u8, u32, bool)> {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Puts back what a test here can change, panic or not.
struct Scene {
    tid: u32,
}

impl Drop for Scene {
    fn drop(&mut self) {
        azos_ipc::cap::degraded_set(false);
        azos_ipc::cap_store::reset(self.tid);
        ipc_task_pool::shim_kill(self.tid);
    }
}

/// `tid` as a ring-3 caller with an empty capability table, the recorder armed
/// and the encoders set.
///
/// Two task tables: `cap_store` resolves TIDs through `ipc_task_pool`, the
/// handler asks this crate's `shims/sched` (see `gpio_typed_lock.rs`). Nothing
/// on this path copies to or from user memory, so the page table is a non-zero
/// sentinel.
fn ring3(tid: u32) -> Scene {
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0x1000);
    azos_sched::set_current_task_tid(tid);
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_recorder(recorder);
    azos_robot::shim_set_encoder(LEFT, RIGHT);
    Scene { tid }
}

fn grant(tid: u32, wheel: u32, perms: CapPerms) -> azos_ipc::cap::Cap<azos_ipc::cap::targets::Motor> {
    azos_ipc::motor_cap::motor_grant_cap(tid, wheel, perms).expect("capability table full")
}

// ── SYS_MOTOR_ANGLE_TYPED (578) ─────────────────────────────────────────────
//
// The wheel from a `Cap<Motor>` with READ, the ticks through an out pointer as
// 8 bytes `i64` little-endian, and 0 or `-errno` as the return. These callers
// need a real page table, so they allocate one.

/// A user page mapped writable in the caller's page table: where the ticks go.
const OUT: usize = 0x0076_0000;
/// A user page mapped read-only.
const RO_PAGE: usize = 0x0077_0000;
/// A non-null user address no test here maps.
const UNMAPPED_OUT: u64 = 0x0079_0000;

/// Every typed denial the typed recorder saw: (kind code, reason code).
static SEEN_TYPED: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());

fn typed_recorder(kind_code: u8, reason_code: u32) {
    SEEN_TYPED.lock().unwrap_or_else(|e| e.into_inner()).push((kind_code, reason_code));
}

fn seen_typed() -> Vec<(u8, u32)> {
    SEEN_TYPED.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// `ring3`, with a real page table holding `OUT` (user read-write) and
/// `RO_PAGE` (user read-only), and both recorders armed. Returns the host
/// address of `OUT`'s frame, filled with `0xAA`, so a test can read back what
/// the call wrote, or that it wrote nothing.
fn ring3_with_pages(tid: u32) -> (Scene, *mut u8) {
    use azos_arch_api::PagePerms;
    let s = ring3(tid);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::set_current_user_pt(pt);
    let out = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, OUT, out, PagePerms::USER_RW).expect("map");
    let ro = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, RO_PAGE, ro, PagePerms::USER_RO).expect("map");
    let out = out as *mut u8;
    // SAFETY: a whole arena page this test just allocated.
    unsafe { core::ptr::write_bytes(out, 0xAA, 8) };
    __cap_deny_limiter_clear_for_tests();
    SEEN_TYPED.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_typed_recorder(typed_recorder);
    (s, out)
}

/// The first eight bytes of `OUT`'s frame.
fn read_out(frame: *mut u8) -> [u8; 8] {
    // SAFETY: `frame` is the arena page `ring3_with_pages` mapped at `OUT`.
    unsafe { core::ptr::read(frame as *const [u8; 8]) }
}

/// A capability as the raw handle a syscall takes.
fn raw<T: azos_ipc::cap::CapTarget>(cap: azos_ipc::cap::Cap<T>) -> u64 {
    cap.raw().as_raw() as u64
}

/// **The ticks of the wheel the capability names, through the pointer**, as
/// `i64` little-endian, with no record. The seeded form, RW, reads too.
///
/// **Canaries.** Swap the two wheels in `sys_motor_angle_typed`: the wheel-0
/// bytes read `RIGHT`. Write `to_be_bytes`: the bytes differ.
#[test]
fn the_typed_angle_call_writes_the_ticks_of_the_wheel_its_capability_names() {
    let _g = serial();
    let tid = fresh_tid();
    let (_s, out) = ring3_with_pages(tid);
    let left = grant(tid, 0, CapPerms::READ);
    let right = grant(tid, 1, CapPerms::RW);

    assert_eq!(sys_motor_angle_typed(raw(left), OUT as u64), 0);
    assert_eq!(read_out(out), LEFT.to_le_bytes(), "wheel 0");
    assert_eq!(sys_motor_angle_typed(raw(right), OUT as u64), 0);
    assert_eq!(read_out(out), RIGHT.to_le_bytes(), "wheel 1, a negative count");
    assert!(seen().is_empty() && seen_typed().is_empty(), "an admitted read wrote a record");
}

/// **A read stays live while contained.**
///
/// **Canary.** Resolve the capability with `WRITE` in `sys_motor_angle_typed`:
/// the contained read reads `-EAGAIN` (with `READ` alone held, `-ECAPPERMS`).
#[test]
fn containment_does_not_refuse_the_typed_angle_call() {
    let _g = serial();
    let tid = fresh_tid();
    let (_s, out) = ring3_with_pages(tid);
    let cap = grant(tid, 0, CapPerms::RW);
    azos_ipc::cap::degraded_set(true);

    assert_eq!(sys_motor_angle_typed(raw(cap), OUT as u64), 0, "a contained read was refused");
    assert_eq!(read_out(out), LEFT.to_le_bytes());
    assert!(seen_typed().is_empty(), "a contained read wrote a record");
}

/// **A refused capability reads no encoder, writes nothing, and is one typed
/// record under Motor.** A WRITE-only capability, a capability of another kind
/// and the forged handle, the last one with a bad pointer: the capability is
/// resolved first, so that is a capability refusal and not `-EFAULT`.
///
/// **Canary.** Check the pointer before the capability: the forged line reads
/// `-EFAULT` and writes no record.
#[test]
fn a_refused_capability_reads_no_encoder_and_writes_one_record() {
    use azos_ipc::cap::{targets::Gpio, CapError};
    let _g = serial();
    let tid = fresh_tid();
    let (_s, out) = ring3_with_pages(tid);
    let write_only = grant(tid, 0, CapPerms::WRITE);
    let gpio = azos_ipc::cap_store::grant::<Gpio>(tid, CapPerms::RW, 5).expect("capability table full");
    let reads = azos_robot::shim_encoder_reads();

    let e = |n: azos_abi::error::Errno| n.to_syscall_ret();
    use azos_abi::error::Errno;
    assert_eq!(sys_motor_angle_typed(raw(write_only), OUT as u64), e(Errno::ECAPPERMS), "WRITE-only");
    assert_eq!(sys_motor_angle_typed(raw(gpio), OUT as u64), e(Errno::ECAPKIND), "a Gpio capability");
    assert_eq!(sys_motor_angle_typed(0, UNMAPPED_OUT), e(Errno::ECAPSTALE), "the forged handle");

    assert_eq!(azos_robot::shim_encoder_reads(), reads, "a refused call read the encoders");
    assert_eq!(read_out(out), [0xAA; 8], "a refused call wrote the out buffer");
    let motor = CapKind::Motor.denial_code();
    assert_eq!(
        seen_typed(),
        vec![
            (motor, CapError::MissingPerms.code()),
            (motor, CapError::WrongKind.code()),
            (motor, CapError::Stale.code()),
        ]
    );
    assert!(seen().is_empty(), "a typed refusal wrote an untyped record");
}

/// **The out pointer must be 8 writable user bytes.** Null, unmapped, a
/// read-only page, and a range whose last bytes cross into an unmapped page
/// are `-EFAULT`. The capability was held, so none of them is a record.
///
/// **Canary.** Ignore `copy_to_user`'s answer: every line reads 0.
#[test]
fn an_out_pointer_that_is_not_writable_user_memory_is_efault() {
    use azos_abi::error::Errno;
    let _g = serial();
    let tid = fresh_tid();
    let (_s, _out) = ring3_with_pages(tid);
    let cap = grant(tid, 0, CapPerms::READ);
    let efault = Errno::EFAULT.to_syscall_ret();

    assert_eq!(sys_motor_angle_typed(raw(cap), 0), efault, "null");
    assert_eq!(sys_motor_angle_typed(raw(cap), UNMAPPED_OUT), efault, "unmapped");
    assert_eq!(sys_motor_angle_typed(raw(cap), RO_PAGE as u64), efault, "a read-only page");
    let straddle = (OUT + azos_arch::mmu::PAGE_SIZE - 4) as u64;
    assert_eq!(sys_motor_angle_typed(raw(cap), straddle), efault, "the last four bytes are unmapped");
    assert!(seen_typed().is_empty() && seen().is_empty(), "a bad pointer wrote a capability record");
}

/// **A capability for a wheel with no encoder is `-EINVAL`, before the
/// encoders are read or the buffer written.** Only 0 and 1 have one.
///
/// **Canary.** Drop the `wheel > 1` check: the call reads 0 and writes
/// `RIGHT`'s ticks.
#[test]
fn a_wheel_with_no_encoder_is_refused_before_anything_is_read() {
    use azos_ipc::cap::targets::Motor;
    let _g = serial();
    let tid = fresh_tid();
    let (_s, out) = ring3_with_pages(tid);
    let third = azos_ipc::cap_store::grant::<Motor>(tid, CapPerms::RW, 2).expect("capability table full");
    let reads = azos_robot::shim_encoder_reads();

    assert_eq!(
        sys_motor_angle_typed(raw(third), OUT as u64),
        azos_abi::error::Errno::EINVAL.to_syscall_ret()
    );
    assert_eq!(azos_robot::shim_encoder_reads(), reads, "the encoders were read for wheel 2");
    assert_eq!(read_out(out), [0xAA; 8], "the buffer was written for wheel 2");
    assert!(seen_typed().is_empty(), "a held capability wrote a record");
}

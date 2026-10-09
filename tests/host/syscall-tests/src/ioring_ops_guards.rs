// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the kernel's io_ring op table (`crates/core/syscall/src/ioring_ops.rs`)
// and the ring handlers in `crates/core/syscall/src/ipc_handlers.rs` (RFC-0041 §E).
//
// **What is real here.** The ring's own checks (`crates/core/ipc/src/io_ring.rs`,
// pulled in whole by `shims/ipc`) run against `KERNEL_IORING_OPS`: the
// submitter's filter through the real `SyscallFilter::verdict_for`, the
// owner's real capability table, the real `motor_set_reporting` with its halt
// rule (`shims/robot`), and the typed call on the same state wherever the two
// doors must give the same answer. The ring page is mapped by the
// `shm_map_user` stand-in into a real Sv39 table and read back through the
// real `translate_user`.
//
// **What is not.** The sensor is the encoder pair `shims/robot` reports, and
// the PWM and GPIO drivers are the probes in `shims/drivers`.
//
// The ring-level rules against a test table — back-pressure, the refusal flag,
// the pair rule — are in `crates/core/ipc/src/io_ring.rs`'s own suite.

use super::harness::serial;
use crate::ioring_ops::KERNEL_IORING_OPS;
use crate::ipc_handlers::{sys_ioring_create_typed, sys_ioring_destroy_typed, sys_ioring_submit_typed};
use azos_abi::cap::{CapKind, CapPerms};
use azos_abi::error::Errno;
use azos_abi::syscall_nr as nr;
use azos_arch_api::PagePerms;
use azos_drv_gpio::gpio::{set_gpio_probe, GpioOp};
use azos_drv_actuator::pwm::{set_pwm_probe, PwmOp};
use azos_ipc::cap::targets::{Motor, Pwm, Sensor};
use azos_ipc::cap::CapTarget;
use azos_ipc::io_ring::{
    CqEntry, IoRing, SqEntry, CQE_F_DURABLE, CQE_F_QUEUED, CQE_F_REFUSED, OP_FSYNC, OP_NET_SEND, OP_CHAN_RECV, OP_CHAN_SEND, OP_FILE_READ, OP_FILE_WRITE,
    OP_MOTOR_SPEED, OP_NOP, OP_PWM_SET, OP_READ_SENSOR, OP_TIMER,
    RING_CQ_SIZE, RING_SQ_SIZE,
};
use azos_sched::filter::SyscallFilter;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;

const SLOT: usize = 60;
static NEXT_TID: AtomicU32 = AtomicU32::new(0x7c10_0001);

/// A page mapped user-RW, where the create writes its address.
const SCRATCH: usize = 0x0074_0000;

/// Wheels 0 and 1: their PWM channels and direction pins.
const CH: [u32; 2] = [4, 5];
const PINS: [(u32, u32); 2] = [(20, 21), (22, 23)];
/// A PWM channel no motor claims.
const FREE_CH: u32 = 2;

static ESTOP: AtomicBool = AtomicBool::new(false);

/// The kernel's halt query: a latched e-stop or containment.
fn test_halt() -> bool {
    ESTOP.load(Ordering::SeqCst) || azos_ipc::cap::degraded_active()
}

fn test_gate(_id: u32, speed_pct: u32) -> u32 {
    if test_halt() { 0 } else { speed_pct }
}

static PWM_CALLS: Mutex<Vec<(PwmOp, u32, u32)>> = Mutex::new(Vec::new());

fn pwm_probe(op: PwmOp, ch: u32, arg: u32) -> i32 {
    PWM_CALLS.lock().unwrap_or_else(|e| e.into_inner()).push((op, ch, arg));
    if op == PwmOp::SetDutyPct { arg as i32 } else { 0 }
}

fn pwm_calls() -> Vec<(PwmOp, u32, u32)> {
    PWM_CALLS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn clear_pwm_calls() {
    PWM_CALLS.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

fn gpio_probe(_op: GpioOp, _pin: u32, _val: u32) -> i32 {
    0
}

/// Puts back every process static a test here touches, panic or not.
struct Scene {
    tid: u32,
}

impl Drop for Scene {
    fn drop(&mut self) {
        azos_ipc::io_ring::io_ring_release_all(self.tid);
        azos_ipc::cap::degraded_set(false);
        ESTOP.store(false, Ordering::SeqCst);
        set_pwm_probe(None);
        set_gpio_probe(None);
        azos_sched::scheduler::set_current_syscall_filter(SyscallFilter::disabled());
        azos_ipc::cap_store::reset(self.tid);
    }
}

/// A ring-3 task with a real page table, `SCRATCH` mapped, an empty
/// capability table, no filter, and the kernel's op table registered.
fn ring3() -> (Scene, usize) {
    let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(tid);
    let scratch = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, SCRATCH, scratch, PagePerms::USER_RW).expect("map");
    azos_sched::scheduler::set_current_syscall_filter(SyscallFilter::disabled());
    azos_ipc::io_ring::io_ring_register_ops(&KERNEL_IORING_OPS);
    (Scene { tid }, pt)
}

fn grant<T: CapTarget>(tid: u32, perms: CapPerms, resource: u32) -> u64 {
    azos_ipc::cap_store::grant::<T>(tid, perms, resource)
        .expect("cap table full")
        .raw()
        .as_raw() as u64
}

/// An enforcing profile listing `allowed`.
fn profile(allowed: &[u64], audit: bool) -> SyscallFilter {
    let mut f = SyscallFilter::disabled();
    f.enabled = true;
    f.audit = audit;
    for &n in allowed {
        f.allow(n as u16);
    }
    f
}

/// Create a ring through the syscall. Answers its capability, the address the
/// call wrote, and the page as the kernel reaches it — found by walking the
/// task's table at that address, so a wrong or unmapped address fails here.
fn create(pt: usize) -> (u64, usize, *mut IoRing) {
    let cap = sys_ioring_create_typed(SCRATCH as u64);
    assert!(cap > 0, "create returned {cap}");
    let mut out = [0u8; 8];
    assert!(azos_sched::copy_from_user(out.as_mut_ptr(), SCRATCH, out.len()));
    let va = u64::from_le_bytes(out) as usize;
    let phys = azos_mm::vmm::translate_user(pt, va, true)
        .expect("the ring page is not mapped user-writable at the address the create returned");
    (cap as u64, va, phys as *mut IoRing)
}

fn sqe(opcode: u16, param0: u32, param1: u32, param2: u32) -> SqEntry {
    SqEntry { opcode, flags: 0, param0, param1, param2, addr: 0, reg: 0, user_data: 0x5eed }
}

/// Queue `e`, submit through the syscall, and consume the completion. Answers
/// the submit's return and the completion.
unsafe fn submit(cap: u64, ring: *mut IoRing, e: SqEntry) -> (i64, CqEntry) {
    let tail = (*ring).sq_tail.load(Ordering::Acquire);
    (*ring).sq_entries[tail as usize % RING_SQ_SIZE] = e;
    (*ring).sq_tail.store(tail.wrapping_add(1), Ordering::Release);
    let cq = (*ring).cq_tail.load(Ordering::Acquire);
    let n = sys_ioring_submit_typed(cap);
    let c = (*ring).cq_entries[cq as usize % RING_CQ_SIZE];
    (*ring).cq_head.store((*ring).cq_tail.load(Ordering::Acquire), Ordering::Release);
    (n, c)
}

fn done(c: CqEntry) -> (i32, u32) {
    (c.result, c.flags)
}

/// Both wheels initialised on the real motor layer, with the kernel's halt
/// query and gate installed and the PWM log emptied of the initialisation.
fn wheels() {
    azos_robot::motor::set_motor_halt(test_halt);
    azos_robot::motor::set_motor_gate(test_gate);
    set_gpio_probe(Some(gpio_probe));
    set_pwm_probe(Some(pwm_probe));
    for id in 0..2 {
        assert_eq!(azos_robot::motor_init(id as u32, CH[id], PINS[id].0, PINS[id].1), 0);
    }
    clear_pwm_calls();
}

// ── The ring page in ring 3 ───────────────────────────────────────────────

/// **The create returns a user address the ring page is mapped at, writable,
/// inside the shm/MMIO window; the destroy removes the PTE and gives the
/// address back.** The completion the kernel writes is read at that address.
///
/// **Canaries.** Delete `unmap_user_pages(va, 1)` from `unmap_ring_page`: the
/// PTE survives the destroy. Delete its `release_user_window` call: the second
/// create gets another address.
#[test]
fn the_ring_page_is_mapped_at_the_returned_address_and_unmapped_on_destroy() {
    let _g = serial();
    let (_s, pt) = ring3();
    let (cap, va, ring) = create(pt);
    let (lo, hi) = azos_sched::user_shm_window();
    assert!(va >= lo && va < hi, "{va:#x} is outside the window [{lo:#x}, {hi:#x})");
    assert_eq!(va % 4096, 0);

    // The kernel writes a completion; ring 3 reads it through its own mapping.
    let (n, _) = unsafe { submit(cap, ring, sqe(OP_NOP, 0, 0, 0)) };
    assert_eq!(n, 1);
    let mut cq_tail = [0u8; 4];
    assert!(azos_sched::copy_from_user(cq_tail.as_mut_ptr(), va + 1036, 4));
    assert_eq!(u32::from_le_bytes(cq_tail), 1, "the user mapping is not the kernel's page");

    assert_eq!(sys_ioring_destroy_typed(cap), 0);
    assert_eq!(azos_mm::vmm::translate_user(pt, va, false), None, "the PTE outlived the ring");
    assert_eq!(sys_ioring_destroy_typed(cap), Errno::ECAPSTALE.to_syscall_ret(), "the capability was revoked");

    let (cap2, va2, _) = create(pt);
    assert_eq!(va2, va, "the destroy did not give the window address back");
    assert_eq!(sys_ioring_destroy_typed(cap2), 0);
}

/// **A kernel refusal of the whole submit is `-EBUSY` when the CQ is full**,
/// and nothing runs: 32 completions nobody read, one more entry pending.
///
/// **Canary.** Map `CqFull` to `EIO` in `errno_for_ioring_err`.
#[test]
fn a_submit_against_a_full_cq_answers_ebusy() {
    let _g = serial();
    let (_s, pt) = ring3();
    let (cap, _va, ring) = create(pt);
    unsafe {
        for i in 0..RING_SQ_SIZE {
            (*ring).sq_entries[i] = sqe(OP_NOP, 0, 0, 0);
        }
        (*ring).sq_tail.store(RING_SQ_SIZE as u32, Ordering::Release);
        assert_eq!(sys_ioring_submit_typed(cap), RING_SQ_SIZE as i64);
        (*ring).sq_tail.store(RING_SQ_SIZE as u32 + 1, Ordering::Release);
        assert_eq!(sys_ioring_submit_typed(cap), Errno::EBUSY.to_syscall_ret());
        assert_eq!((*ring).sq_head.load(Ordering::Acquire), RING_SQ_SIZE as u32);
    }
}

// ── Seccomp per entry ─────────────────────────────────────────────────────

/// **A profile without `SYS_SENSOR_READ_TYPED` refuses the ring's sensor read,
/// and the encoders are not read**, although the capability is held. In audit
/// mode the same entry runs; listed, it runs.
///
/// **Canary.** Answer `true` from the `Deny` arm of `syscall_allowed`: the
/// entry reads 16 bytes and the encoders.
#[test]
fn a_profile_without_the_sensor_read_refuses_the_ring_read_and_reads_nothing() {
    let _g = serial();
    let (s, pt) = ring3();
    grant::<Sensor>(s.tid, CapPerms::READ, SENSOR_TYPE_ENCODER as u32);
    azos_robot::shim_set_encoder(11, -7);
    let (cap, _va, ring) = create(pt);
    let e = sqe(OP_READ_SENSOR, SENSOR_TYPE_ENCODER as u32, 0, 16);

    azos_sched::scheduler::set_current_syscall_filter(profile(&[nr::SYS_IORING_SUBMIT_TYPED], false));
    let reads = azos_robot::shim_encoder_reads();
    let (n, c) = unsafe { submit(cap, ring, e) };
    assert_eq!(n, 1, "a refused entry still completes");
    assert_eq!(done(c), (Errno::EPERM.to_syscall_ret() as i32, CQE_F_REFUSED));
    assert_eq!(azos_robot::shim_encoder_reads(), reads, "a denied entry read the encoders");

    azos_sched::scheduler::set_current_syscall_filter(profile(&[nr::SYS_IORING_SUBMIT_TYPED], true));
    let (_, c) = unsafe { submit(cap, ring, e) };
    assert_eq!(done(c), (16, 0), "audit mode lets the entry through");

    azos_sched::scheduler::set_current_syscall_filter(profile(&[nr::SYS_SENSOR_READ_TYPED], false));
    let (_, c) = unsafe { submit(cap, ring, e) };
    assert_eq!(done(c), (16, 0), "a listed call runs");
    let bytes = unsafe { &(&(*ring).data_buf)[..16] };
    assert_eq!(bytes[..8], 11i64.to_le_bytes());
    assert_eq!(bytes[8..], (-7i64).to_le_bytes());
}

/// **A profile without `SYS_MOTOR_SPEED_TYPED` refuses the motor entry, and no
/// PWM channel is written.**
///
/// **Canary.** Delete the `syscall_allowed` check from `dispatch_sqe`: both
/// wheels are driven.
#[test]
fn a_profile_without_the_motor_call_refuses_the_motor_entry_and_moves_nothing() {
    let _g = serial();
    let (s, pt) = ring3();
    grant::<Motor>(s.tid, CapPerms::RW, 0);
    grant::<Motor>(s.tid, CapPerms::RW, 1);
    wheels();
    let (cap, _va, ring) = create(pt);
    azos_sched::scheduler::set_current_syscall_filter(profile(&[nr::SYS_IORING_SUBMIT_TYPED], false));
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_MOTOR_SPEED, 30, 30, 0)) };
    assert_eq!(done(c), (Errno::EPERM.to_syscall_ret() as i32, CQE_F_REFUSED));
    assert!(pwm_calls().is_empty(), "a denied motor entry wrote {:?}", pwm_calls());
}

// ── Capability per entry, through the kernel's sensor read ────────────────

/// **Without the capability the sensor entry is refused with `-ECAPPERMS` and
/// the encoders are not read; with it, the entry's bytes are the typed call's
/// bytes.** One function behind both doors.
///
/// **Canary.** Drop `need_cap!` from `OP_READ_SENSOR` in `io_ring.rs`: the
/// unheld entry reads the encoders.
#[test]
fn a_sensor_entry_needs_the_capability_and_reads_what_the_typed_call_reads() {
    let _g = serial();
    let (s, pt) = ring3();
    azos_robot::shim_set_encoder(1234, 5678);
    let (cap, _va, ring) = create(pt);
    let e = sqe(OP_READ_SENSOR, SENSOR_TYPE_ENCODER as u32, 0, 16);

    let reads = azos_robot::shim_encoder_reads();
    let (_, c) = unsafe { submit(cap, ring, e) };
    assert_eq!(done(c), (Errno::ECAPPERMS.to_syscall_ret() as i32, CQE_F_REFUSED));
    assert_eq!(azos_robot::shim_encoder_reads(), reads, "an unheld entry read the encoders");

    let sensor = grant::<Sensor>(s.tid, CapPerms::READ, SENSOR_TYPE_ENCODER as u32);
    let (_, c) = unsafe { submit(cap, ring, e) };
    assert_eq!(done(c), (16, 0));
    let typed = sys_sensor_read_typed(sensor, SCRATCH as u64, 16);
    assert_eq!(typed, 16);
    let mut via_typed = [0u8; 16];
    assert!(azos_sched::copy_from_user(via_typed.as_mut_ptr(), SCRATCH, 16));
    assert_eq!(unsafe { (&(*ring).data_buf)[..16].to_vec() }, via_typed.to_vec());
}

// ── Actuation authority ───────────────────────────────────────────────────

/// **A motor entry during a latched e-stop does not move either wheel.** The
/// halt rule refuses both commands in the motor layer, each writes duty 0 and
/// records speed 0, and the entry completes refused with `-EAGAIN`, the answer
/// `SYS_MOTOR_SPEED_TYPED` gives on the same state. Released, the same entry
/// drives both wheels: the refusal is the latch, not the path.
///
/// **Canary.** Make `motor_wheel` write the channel itself
/// (`pwm_set_duty_pct(CH, speed)` in place of `motor_set_reporting`): the
/// latched entry writes duty 60.
#[test]
fn a_motor_entry_under_a_latched_estop_holds_both_wheels_at_duty_zero() {
    let _g = serial();
    let (s, pt) = ring3();
    let wheel0 = grant::<Motor>(s.tid, CapPerms::RW, 0);
    grant::<Motor>(s.tid, CapPerms::RW, 1);
    wheels();
    let (cap, _va, ring) = create(pt);

    ESTOP.store(true, Ordering::SeqCst);
    let (n, c) = unsafe { submit(cap, ring, sqe(OP_MOTOR_SPEED, 60, 60, 0)) };
    assert_eq!(n, 1);
    assert_eq!(done(c), (E_CONTAINED as i32, CQE_F_REFUSED));
    assert_eq!(
        pwm_calls(),
        vec![(PwmOp::SetDutyPct, CH[0], 0), (PwmOp::SetDutyPct, CH[1], 0)],
        "a wheel was driven under a latched e-stop"
    );
    for id in 0..2 {
        assert!(
            matches!(azos_robot::motor_state(id), Some((_, 0))),
            "wheel {id} recorded a speed under the latch"
        );
    }
    clear_pwm_calls();
    assert_eq!(sys_motor_speed_typed(wheel0, 60), E_CONTAINED, "the typed call on the same state");

    ESTOP.store(false, Ordering::SeqCst);
    clear_pwm_calls();
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_MOTOR_SPEED, 60, 60, 0)) };
    assert_eq!(done(c), (0, 0));
    assert_eq!(pwm_calls(), vec![(PwmOp::SetDutyPct, CH[0], 60), (PwmOp::SetDutyPct, CH[1], 60)]);
}

/// **Containment refuses the PWM entry with the code the typed call returns,
/// and writes nothing; a read-only entry on the same ring keeps running.**
///
/// **Canary.** Delete `not_contained!()` from `OP_PWM_SET` in `io_ring.rs`:
/// the contained entry writes duty 40.
#[test]
fn containment_refuses_the_pwm_entry_with_the_typed_code_and_keeps_reads_running() {
    let _g = serial();
    let (s, pt) = ring3();
    let pwm = grant::<Pwm>(s.tid, CapPerms::RW, FREE_CH);
    grant::<Sensor>(s.tid, CapPerms::READ, SENSOR_TYPE_ENCODER as u32);
    set_pwm_probe(Some(pwm_probe));
    clear_pwm_calls();
    let (cap, _va, ring) = create(pt);

    azos_ipc::cap::degraded_set(true);
    let typed = sys_pwm_set_duty_pct_typed(pwm, 40);
    assert_eq!(typed, Errno::EAGAIN.to_syscall_ret(), "precondition: the typed call is contained");
    let (n, c) = unsafe { submit(cap, ring, sqe(OP_PWM_SET, FREE_CH, 40, 0)) };
    assert_eq!(n, 1, "the submit itself is not refused while contained");
    assert_eq!(done(c), (typed as i32, CQE_F_REFUSED));
    assert!(pwm_calls().is_empty(), "a contained entry wrote {:?}", pwm_calls());
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_READ_SENSOR, SENSOR_TYPE_ENCODER as u32, 0, 16)) };
    assert_eq!(done(c), (16, 0), "a read on the same ring");

    azos_ipc::cap::degraded_set(false);
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_PWM_SET, FREE_CH, 40, 0)) };
    assert_eq!(c.flags, 0, "released, the entry runs");
    assert_eq!(pwm_calls(), vec![(PwmOp::SetDutyPct, FREE_CH, 40)]);
}

// ── File, channel and timer entries on the kernel's table ─────────────────

/// A filesystem stand-in: fd 3 is open, owned by [`FD3_OWNER`]; a read fills
/// with `R`. Its access rules are the kernel's (`kernel/src/boot/seams.rs`):
/// `read`/`write` ask about the RUNNING task through `fd_access_allowed`
/// (a kernel caller, `user_pt == 0`, passes), `read_as`/`write_as` ask
/// whether the descriptor is the named task's through `fd_owned_by`.
struct RingDisk;

/// The owner stamp of fd 3 (0: unowned). `file_scene` stamps the running task.
static FD3_OWNER: AtomicU32 = AtomicU32::new(0);

fn fd3_owner() -> Option<u32> {
    match FD3_OWNER.load(Ordering::SeqCst) { 0 => None, o => Some(o) }
}

fn fd3_usable_by_caller() -> bool {
    crate::file_ops::fd_access_allowed(
        fd3_owner(),
        azos_sched::current_task_tid(),
        azos_sched::current_user_pt() == 0,
        0,
    )
}

impl crate::file_ops::FileOps for RingDisk {
    fn open(&self, _path: &[u8], _flags: u32) -> i64 { -1 }
    fn close(&self, _fd: i32) -> i64 { -1 }
    fn read(&self, fd: i32, dst: &mut [u8]) -> i64 {
        if fd != 3 || !fd3_usable_by_caller() { return -1; }
        for b in dst.iter_mut() { *b = b'R'; }
        dst.len() as i64
    }
    fn write(&self, fd: i32, src: &[u8]) -> i64 {
        if fd != 3 || !fd3_usable_by_caller() { return -1; }
        FILE_WRITES.lock().unwrap_or_else(|e| e.into_inner()).push(src.to_vec());
        src.len() as i64
    }
    fn read_as(&self, tid: u32, fd: i32, dst: &mut [u8]) -> i64 {
        if fd != 3 || !crate::file_ops::fd_owned_by(fd3_owner(), tid, 0) { return -1; }
        for b in dst.iter_mut() { *b = b'R'; }
        dst.len() as i64
    }
    fn write_as(&self, tid: u32, fd: i32, src: &[u8]) -> i64 {
        if fd != 3 || !crate::file_ops::fd_owned_by(fd3_owner(), tid, 0) { return -1; }
        FILE_WRITES.lock().unwrap_or_else(|e| e.into_inner()).push(src.to_vec());
        src.len() as i64
    }
    fn fsync_request_as(&self, tid: u32, fd: i32) -> Result<u64, i64> {
        if fd != 3 || !crate::file_ops::fd_owned_by(fd3_owner(), tid, 0) {
            return Err(Errno::EBADF.to_syscall_ret());
        }
        Ok(FLUSH_ASKED.fetch_add(1, Ordering::SeqCst) as u64 + 1)
    }
    fn fsync_done(&self, ticket: u64) -> Option<i64> {
        (FLUSH_DONE.load(Ordering::SeqCst) as u64 >= ticket).then_some(0)
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

static RING_DISK: RingDisk = RingDisk;
/// `RingDisk`'s flush tickets: asked, and done (the test is the flusher).
static FLUSH_ASKED: AtomicU32 = AtomicU32::new(0);
static FLUSH_DONE: AtomicU32 = AtomicU32::new(0);
static FILE_WRITES: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

/// Every typed denial record, `(kind code, reason code)`.
static TYPED_SEEN: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());
fn typed_recorder(kind: u8, reason: u32) {
    TYPED_SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((kind, reason));
}
fn typed_seen() -> Vec<(u8, u32)> {
    TYPED_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Uninstalls the stand-in filesystem and the recorder, panic or not.
struct FileScene;
impl Drop for FileScene {
    fn drop(&mut self) {
        crate::file_ops::__file_ops_clear_for_tests();
        FD3_OWNER.store(0, Ordering::SeqCst);
        TYPED_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
        FILE_WRITES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

fn file_scene() -> FileScene {
    crate::file_ops::set_file_ops(&RING_DISK);
    FD3_OWNER.store(azos_sched::current_task_tid(), Ordering::SeqCst);
    TYPED_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    FILE_WRITES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    crate::handlers::set_cap_deny_typed_recorder(typed_recorder);
    FileScene
}

/// **A file entry is the typed file call below the trap**: the owner's
/// `Cap<File>` is resolved with `CapTable::get` — `READ` for a read, `WRITE`
/// with containment for a write — the descriptor is read into the ring's
/// buffer, and a refusal is recorded as the typed call records it
/// (`SAFETY_CAP_DENIED_TYPED`, File, `MissingPerms`), while containment
/// refuses with `-EAGAIN` and records nothing.
///
/// **Canaries.** Resolve with `CapPerms::READ` for both directions: the write
/// through a READ-only handle completes 8. Delete the `note_typed_denial_for`
/// call in `refuse`: `typed_seen()` stays empty. Resolve with
/// `get_uncontained`: the contained write completes 8.
#[test]
fn a_file_entry_resolves_the_owners_handle_and_records_a_refusal() {
    use azos_ipc::cap::targets::File;
    use azos_ipc::cap::CapError;
    let _g = serial();
    let (s, pt) = ring3();
    let _f = file_scene();
    let (cap, _va, ring) = create(pt);
    let rd = grant::<File>(s.tid, CapPerms::READ, 3) as u32;
    let rw = grant::<File>(s.tid, CapPerms::RW, 3) as u32;

    let (n, c) = unsafe { submit(cap, ring, sqe(OP_FILE_READ, rd, 0, 16)) };
    assert_eq!((n, done(c)), (1, (16, 0)));
    assert!(unsafe { (&(*ring).data_buf)[..16].iter().all(|&b| b == b'R') }, "the read did not land in the window");

    let (_, c) = unsafe { submit(cap, ring, sqe(OP_FILE_WRITE, rd, 0, 8)) };
    assert_eq!(done(c), (Errno::ECAPPERMS.to_syscall_ret() as i32, CQE_F_REFUSED));
    assert_eq!(typed_seen(), vec![(CapKind::File.denial_code(), CapError::MissingPerms.code())]);
    assert!(FILE_WRITES.lock().unwrap().is_empty(), "a refused write reached the file");

    let (_, c) = unsafe { submit(cap, ring, sqe(OP_FILE_WRITE, rw, 0, 8)) };
    assert_eq!(done(c), (8, CQE_F_QUEUED), "a write completes queued (K1)");

    azos_ipc::cap::degraded_set(true);
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_FILE_WRITE, rw, 0, 8)) };
    assert_eq!(done(c), (Errno::EAGAIN.to_syscall_ret() as i32, CQE_F_REFUSED), "a contained write ran");
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_FILE_READ, rd, 0, 4)) };
    assert_eq!(done(c), (4, 0), "containment stopped a read");
    azos_ipc::cap::degraded_set(false);
    assert_eq!(typed_seen().len(), 1, "containment was recorded as a denial");
    assert_eq!(FILE_WRITES.lock().unwrap().len(), 1);
}

/// **K1: an `OP_FSYNC` entry is `SYS_FSYNC_TYPED` below the trap, without
/// the wait.** The owner's `Cap<File>` resolves with any permission (a READ
/// handle syncs, as Linux's fsync on a read-only descriptor); a forged handle
/// is refused `-ECAPSTALE` and recorded. The submit answers no completion for
/// it: the entry parks on its flush ticket and completes `CQE_F_DURABLE` only
/// when the flusher posts (`io_ring_flush_posted`).
///
/// **Canary** `ioring-sync-fsync-canary` (shim ipc): the fsync completes in
/// the submit, `n == 1`.
#[test]
fn an_fsync_entry_resolves_the_owners_handle_and_completes_after_the_flush() {
    use azos_ipc::cap::targets::File;
    use azos_ipc::cap::CapError;
    let _g = serial();
    let (s, pt) = ring3();
    let _f = file_scene();
    let (cap, _va, ring) = create(pt);
    let rd = grant::<File>(s.tid, CapPerms::READ, 3) as u32;

    let (n, c) = unsafe { submit(cap, ring, sqe(OP_FSYNC, 0xDEAD_0000, 0, 0)) };
    assert_eq!((n, done(c)), (1, (Errno::ECAPSTALE.to_syscall_ret() as i32, CQE_F_REFUSED)));
    assert_eq!(typed_seen(), vec![(CapKind::File.denial_code(), CapError::Stale.code())]);

    let asked = FLUSH_ASKED.load(Ordering::SeqCst);
    let (n, _) = unsafe { submit(cap, ring, sqe(OP_FSYNC, rd, 0, 0)) };
    assert_eq!(n, 0, "the fsync completed in the submit, before its flush");
    assert_eq!(FLUSH_ASKED.load(Ordering::SeqCst), asked + 1, "the fsync asked for no flush");
    let cq = unsafe { (*ring).cq_tail.load(Ordering::Acquire) };
    FLUSH_DONE.store(asked + 1, Ordering::SeqCst);
    azos_ipc::io_ring::io_ring_flush_posted();
    let c = unsafe { (*ring).cq_entries[cq as usize % RING_CQ_SIZE] };
    assert_eq!(unsafe { (*ring).cq_tail.load(Ordering::Acquire) }, cq.wrapping_add(1), "the flush posted nothing");
    assert_eq!((c.user_data, done(c)), (0x5eed, (0, CQE_F_DURABLE)));
}

/// **K1: an RT submitter's file entry is handed to the worker** on the real
/// kernel table: the submit completes nothing and the file is untouched; the
/// worker's pass (`io_ring_worker_pass`) runs it with the OWNER's handle and
/// completes it `CQE_F_QUEUED`. A task outside the RT band runs it inline.
///
/// **Canary.** `may_block` answering `true` for every task: the RT submit
/// writes the file (`n == 1`).
#[test]
fn an_rt_file_entry_is_handed_to_the_worker_on_the_kernel_table() {
    use azos_ipc::cap::targets::File;
    let _g = serial();
    let (s, pt) = ring3();
    let _f = file_scene();
    let (cap, _va, ring) = create(pt);
    let rw = grant::<File>(s.tid, CapPerms::RW, 3) as u32;
    azos_sched::scheduler::shim_set_base_priority(azos_sched::RT_PRIORITY_THRESHOLD - 1);
    let (n, _) = unsafe { submit(cap, ring, sqe(OP_FILE_WRITE, rw, 0, 8)) };
    let wrote_in_submit = FILE_WRITES.lock().unwrap().len();
    let cq = unsafe { (*ring).cq_tail.load(Ordering::Acquire) };
    let ran = azos_ipc::io_ring::io_ring_worker_pass();
    azos_sched::scheduler::shim_set_base_priority(20);
    assert_eq!((n, wrote_in_submit), (0, 0), "the RT submit ran its file entry");
    assert_eq!(ran, 1, "the worker had nothing to run");
    let c = unsafe { (*ring).cq_entries[cq as usize % RING_CQ_SIZE] };
    assert_eq!(done(c), (8, CQE_F_QUEUED));
    assert_eq!(FILE_WRITES.lock().unwrap().len(), 1, "the worker did not write the owner's file");
    // Outside the RT band: inline, as before.
    let (n, c) = unsafe { submit(cap, ring, sqe(OP_FILE_WRITE, rw, 0, 8)) };
    assert_eq!((n, done(c)), (1, (8, CQE_F_QUEUED)));
}

/// **K1: `OP_NET_SEND` is `SYS_SEND_TYPED` below the trap, without the
/// wait.** The SQE names a `Cap<Socket>` in the owner's table: a READ-only
/// handle is refused `-ECAPPERMS` and recorded as a Socket denial, a forged
/// one `-ECAPSTALE`; a WRITE handle on a socket another task owns is refused
/// (the owner stamp, as `socket_access_ok`); a WRITE handle on the owner's
/// own socket reaches `socket_send` and answers its count unflagged: an
/// unconnected datagram socket has nowhere to send (`-1`), and nothing
/// waited (no ARP or window yield loop).
///
/// **Canaries.** Resolve with `READ`: the READ handle reaches the socket.
/// Drop the owner-stamp check: the stranger's socket answers -1, unrefused.
#[test]
fn a_net_send_entry_resolves_the_owners_socket_cap_and_never_waits() {
    use azos_ipc::cap::targets::Socket;
    use azos_ipc::cap::CapError;
    let _g = serial();
    let (s, pt) = ring3();
    let _f = file_scene();
    let (cap, _va, ring) = create(pt);
    let mine = azos_net::socket_create_owned(azos_net::socket::AF_INET, azos_net::socket::SOCK_DGRAM,
        azos_net::socket::IPPROTO_UDP, s.tid);
    let theirs = azos_net::socket_create_owned(azos_net::socket::AF_INET, azos_net::socket::SOCK_DGRAM,
        azos_net::socket::IPPROTO_UDP, s.tid + 1000);
    assert!(mine >= 0 && theirs >= 0);
    let ro = grant::<Socket>(s.tid, CapPerms::READ, mine as u32) as u32;
    let wo = grant::<Socket>(s.tid, CapPerms::WRITE, mine as u32) as u32;
    let stranger = grant::<Socket>(s.tid, CapPerms::WRITE, theirs as u32) as u32;

    let (_, c) = unsafe { submit(cap, ring, sqe(OP_NET_SEND, ro, 0, 4)) };
    assert_eq!(done(c), (Errno::ECAPPERMS.to_syscall_ret() as i32, CQE_F_REFUSED));
    assert_eq!(typed_seen(), vec![(CapKind::Socket.denial_code(), CapError::MissingPerms.code())]);
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_NET_SEND, 0xDEAD_0000, 0, 4)) };
    assert_eq!(done(c), (Errno::ECAPSTALE.to_syscall_ret() as i32, CQE_F_REFUSED));
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_NET_SEND, stranger, 0, 4)) };
    assert_eq!(done(c), (crate::handlers::E_PERM as i32, CQE_F_REFUSED), "a stranger's socket was reached");
    let (n, c) = unsafe { submit(cap, ring, sqe(OP_NET_SEND, wo, 0, 4)) };
    assert_eq!((n, done(c)), (1, (-1, 0)), "the owner's socket was not reached, or the answer was flagged");
    azos_net::socket_close(mine);
    azos_net::socket_close(theirs);
}

/// **A channel entry is the typed channel call below the trap**, on a real
/// channel: a message sent through the ring is received through the ring, an
/// empty channel answers the typed call's `-EAGAIN` unflagged, and a forged
/// handle is refused `-ECAPSTALE` and recorded as a Channel denial.
///
/// **Canaries.** Map `Empty` to `Err`: the empty receive comes back flagged.
/// Swap `chan_send`/`chan_recv` in `KERNEL_IORING_OPS`: the send reads an
/// empty channel.
#[test]
fn a_channel_entry_sends_and_receives_on_the_owners_channel() {
    use azos_ipc::cap::CapError;
    let _g = serial();
    let (_s, pt) = ring3();
    let _f = file_scene();
    let (cap, _va, ring) = create(pt);
    let ch = crate::ipc_handlers::sys_chan_create_typed();
    assert!(ch > 0, "channel create {ch}");
    let ch = ch as u32;
    unsafe { (&mut (*ring).data_buf)[..5].copy_from_slice(b"hello"); }

    let (_, c) = unsafe { submit(cap, ring, sqe(OP_CHAN_SEND, ch, 0, 5)) };
    assert_eq!(done(c), (0, 0));
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_CHAN_RECV, ch, 64, 32)) };
    assert_eq!(done(c), (5, 0));
    assert_eq!(unsafe { &(&(*ring).data_buf)[64..69] }, b"hello");
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_CHAN_RECV, ch, 64, 32)) };
    assert_eq!(done(c), (Errno::EAGAIN.to_syscall_ret() as i32, 0), "an empty channel is the call's answer");

    // The null handle: `Stale`, the answer every typed call gives a forgery.
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_CHAN_SEND, 0, 0, 5)) };
    assert_eq!(done(c), (Errno::ECAPSTALE.to_syscall_ret() as i32, CQE_F_REFUSED));
    assert_eq!(typed_seen(), vec![(CapKind::Channel.denial_code(), CapError::Stale.code())]);
    let _ = crate::handlers::sys_close_typed(ch as u64);
}

/// **A timer entry with a passed deadline completes 1 at once; a future one
/// parks, and an empty submit reaps it once the counter passes it.** On the
/// kernel's clock (`timebase::now` in `shims/drivers`).
#[test]
fn a_timer_entry_on_the_kernel_clock() {
    let _g = serial();
    let (_s, pt) = ring3();
    let (cap, _va, ring) = create(pt);
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_TIMER, 0, 0, 0)) };
    assert_eq!(done(c), (1, 0), "deadline 0 has passed");
    let far = u64::MAX / 2;
    let (n, _) = unsafe { submit(cap, ring, sqe(OP_TIMER, far as u32, (far >> 32) as u32, 0)) };
    assert_eq!(n, 0, "a far deadline completed");
    // 100 ns is one tick at 10 MHz: at tick 0 it is ahead, at tick 1 reached.
    let (n, _) = unsafe { submit(cap, ring, sqe(OP_TIMER, 100, 0, 0)) };
    assert_eq!(n, 0);
    azos_drv_irqchip::clint::set_time(1);
    let cq = unsafe { (*ring).cq_tail.load(Ordering::Acquire) };
    assert_eq!(sys_ioring_submit_typed(cap), 1, "an empty submit did not reap the passed timer");
    assert_eq!(done(unsafe { (*ring).cq_entries[cq as usize % RING_CQ_SIZE] }), (0, 0));
    azos_drv_irqchip::clint::set_time(0);
}

// ── The SQ poller: the owner's authority from a kernel context ────────────

/// The TID the poller runs as in these tests; no cap table, no filter entry.
const POLLER_TID: u32 = 0x7c1f_0001;
fn test_spawn(_r: u32, _owner: u32) -> Option<u32> { Some(POLLER_TID) }
fn test_wake(_t: u32) {}
static TEST_SQPOLL: azos_ipc::io_ring::SqpollHooks =
    azos_ipc::io_ring::SqpollHooks { spawn: test_spawn, wake: test_wake };

fn clock() -> u64 { 1000 }
fn summary_hook(_kind: u8, _count: u32) {}

/// Clears what the poller tests install, panic or not.
struct PollerScene;
impl Drop for PollerScene {
    fn drop(&mut self) {
        crate::handlers::__cap_deny_limiter_clear_for_tests();
        azos_sched::scheduler::shim_set_task_filter(POLLER_TID, None);
        azos_sched::set_current_task_tid(0);
    }
}

/// A ring-3 owner whose ring an SQ poller runs: the scene, the owner's TID,
/// the ring page and the packed reference the poller passes.
fn polled_ring() -> (Scene, PollerScene, FileScene, u32, *mut IoRing, u32) {
    use azos_ipc::cap::{targets::IoRing as RingT, Cap, CapHandle};
    let (s, pt) = ring3();
    let f = file_scene();
    azos_ipc::io_ring::io_ring_register_sqpoll(&TEST_SQPOLL);
    assert!(azos_ipc::io_ring::io_ring_permit_sqpoll(s.tid, 20));
    let (cap, _va, ring) = create(pt);
    let (n, c) = unsafe { submit(cap, ring, sqe(azos_ipc::io_ring::OP_SQPOLL_START, 0, 0, 0)) };
    assert_eq!((n, done(c)), (1, (0, 0)), "the poller did not start");
    let rc: Cap<RingT> = Cap::from_raw(CapHandle::from_raw(cap as u32));
    let r = azos_ipc::cap_store::with_table(s.tid, |t| t.get_uncontained(rc, CapPerms::WRITE))
        .unwrap()
        .unwrap();
    let tid = s.tid;
    (s, PollerScene, f, tid, ring, r)
}

/// Queue `e` and run ONE poller pass as the poller task; the completion.
unsafe fn poll_one(ring: *mut IoRing, r: u32, e: SqEntry) -> CqEntry {
    let tail = (*ring).sq_tail.load(Ordering::Acquire);
    (*ring).sq_entries[tail as usize % RING_SQ_SIZE] = e;
    (*ring).sq_tail.store(tail.wrapping_add(1), Ordering::Release);
    let cq = (*ring).cq_tail.load(Ordering::Acquire);
    let owner = azos_sched::current_task_tid();
    azos_sched::set_current_task_tid(POLLER_TID);
    let p = azos_ipc::io_ring::io_ring_sqpoll_pass(r);
    azos_sched::set_current_task_tid(owner);
    assert!(matches!(p, azos_ipc::io_ring::SqpollPass::Done { ran: 1, .. }), "{p:?}");
    let c = (*ring).cq_entries[cq as usize % RING_CQ_SIZE];
    (*ring).cq_head.store((*ring).cq_tail.load(Ordering::Acquire), Ordering::Release);
    c
}

/// **A poller pass is decided by the OWNER's seccomp profile**, read from the
/// owner's slot, not by the poller's (a kernel task, unfiltered): a profile
/// without `SYS_FILE_READ_TYPED` refuses the owner's granted file read through
/// the poller with `-EPERM`, and an owner that is no longer a live task
/// refuses every entry.
///
/// **Canary.** Answer `current_syscall_verdict(nr)` in both arms of
/// `syscall_allowed`: the read runs (the poller is unfiltered).
#[test]
fn a_poller_pass_asks_the_owners_profile_not_the_pollers() {
    use azos_ipc::cap::targets::File;
    let _g = serial();
    let (_s, _p, _f, owner, ring, r) = polled_ring();
    let rd = grant::<File>(owner, CapPerms::READ, 3) as u32;
    azos_sched::scheduler::shim_set_task_filter(owner, Some(SyscallFilter::disabled()));
    let c = unsafe { poll_one(ring, r, sqe(OP_FILE_READ, rd, 0, 16)) };
    assert_eq!(done(c), (16, 0), "the owner's granted read was refused");

    azos_sched::scheduler::shim_set_task_filter(owner, Some(profile(&[nr::SYS_IORING_SUBMIT_TYPED], false)));
    let c = unsafe { poll_one(ring, r, sqe(OP_FILE_READ, rd, 0, 16)) };
    assert_eq!(done(c), (Errno::EPERM.to_syscall_ret() as i32, CQE_F_REFUSED), "ran past the owner's profile");

    azos_sched::scheduler::shim_set_task_filter(owner, None);
    let c = unsafe { poll_one(ring, r, sqe(OP_FILE_READ, rd, 0, 16)) };
    assert_eq!(done(c), (Errno::EPERM.to_syscall_ret() as i32, CQE_F_REFUSED), "a dead owner's entry ran");
}

/// **SQPOLL on a ring whose owner lacks the capability: the entry is refused
/// and RECORDED exactly as the syscall path records it** — the same typed
/// record, charged to the OWNER's per-task bound. The owner spends its four
/// admits on its own typed refusals; the poller's refusal of the owner's entry
/// is then suppressed, as a fifth refusal by the owner would be. Charged to
/// the poller (whose bound is untouched) it would have been written.
///
/// **Canary.** In `note_typed_denial_for`, call `admit_denial_record(..)`
/// (the running task's bound) instead of `admit_denial_record_for(tid, ..)`:
/// a fifth record appears.
#[test]
fn a_poller_refusal_is_recorded_against_the_owner_as_the_syscall_would_be() {
    use azos_ipc::cap::CapError;
    let _g = serial();
    let (_s, _p, _f, owner, ring, r) = polled_ring();
    azos_sched::scheduler::shim_set_task_filter(owner, Some(SyscallFilter::disabled()));
    crate::handlers::set_cap_deny_limiter(clock, 1_000_000, summary_hook);

    // The owner's own typed refusal, once: recorded.
    assert_eq!(crate::handlers::sys_file_read_typed(0, 0, 0), Errno::ECAPSTALE.to_syscall_ret());
    // The poller's refusal of the owner's entry: recorded, as the same record.
    let c = unsafe { poll_one(ring, r, sqe(azos_ipc::io_ring::OP_WRITE_GPIO, 7, 1, 0)) };
    assert_eq!(done(c), (Errno::ECAPPERMS.to_syscall_ret() as i32, CQE_F_REFUSED));
    assert_eq!(
        typed_seen(),
        vec![
            (CapKind::File.denial_code(), CapError::Stale.code()),
            (CapKind::Gpio.denial_code(), CapError::MissingPerms.code()),
        ]
    );
    // Two more of the owner's own: its bound of four is spent.
    for _ in 0..2 {
        let _ = crate::handlers::sys_file_read_typed(0, 0, 0);
    }
    assert_eq!(typed_seen().len(), 4);
    // The poller refuses the owner's entry again: suppressed, like the owner's
    // fifth refusal.
    let c = unsafe { poll_one(ring, r, sqe(azos_ipc::io_ring::OP_WRITE_GPIO, 7, 1, 0)) };
    assert_eq!(done(c).1, CQE_F_REFUSED);
    assert_eq!(typed_seen().len(), 4, "the poller's refusal was charged to the poller, not the owner");
}

/// **The actuation gate per entry under SQPOLL.** A motor entry the poller
/// runs under a latched e-stop holds both wheels at duty 0 and completes
/// refused, as the submitted entry does.
#[test]
fn a_poller_motor_entry_under_a_latched_estop_holds_both_wheels_at_duty_zero() {
    let _g = serial();
    let (_s, _p, _f, owner, ring, r) = polled_ring();
    azos_sched::scheduler::shim_set_task_filter(owner, Some(SyscallFilter::disabled()));
    grant::<Motor>(owner, CapPerms::RW, 0);
    grant::<Motor>(owner, CapPerms::RW, 1);
    wheels();
    ESTOP.store(true, Ordering::SeqCst);
    let c = unsafe { poll_one(ring, r, sqe(OP_MOTOR_SPEED, 50, 50, 0)) };
    assert_eq!(done(c), (Errno::EAGAIN.to_syscall_ret() as i32, CQE_F_REFUSED));
    let duties: Vec<u32> = pwm_calls().iter().filter(|c| c.0 == PwmOp::SetDutyPct).map(|c| c.2).collect();
    assert_eq!(duties, vec![0, 0], "a wheel moved under a latched e-stop");
}

// ── OVSwrap review F1: a gifted or stale `Cap<File>` through the poller ────

/// **The poller reads a file only if the descriptor is the ring OWNER's.**
/// A `Cap<File>` holds a bare descriptor number; a move copies it into another
/// task's table without re-stamping the owner, and the number is reused once
/// its opener closes it or exits. The owner here holds a `Cap<File>` on fd 3
/// while fd 3 is stamped to ANOTHER task (the victim that reopened the
/// number). Run as the poller — a kernel task, `user_pt == 0`, which the
/// running-task check (`fd_access_allowed`) admits for every descriptor — the
/// read and the write must come back `-1` and touch nothing. With fd 3
/// stamped back to the owner, the same entries run: the refusal is the owner
/// check, not a broken ring.
///
/// **Canary (by hand, 2026-10-02).** In `ioring_ops::file_io`, call
/// `ops.read`/`ops.write` instead of `read_as`/`write_as`: the poller's read
/// completes 16 with the victim's bytes and the write lands, and this test
/// fails on "the poller read a descriptor the owner does not own".
#[test]
fn a_poller_file_entry_on_a_descriptor_the_owner_does_not_own_is_refused() {
    use azos_ipc::cap::targets::File;
    let _g = serial();
    let (_s, _p, _f, owner, ring, r) = polled_ring();
    let rw = grant::<File>(owner, CapPerms::RW, 3) as u32;
    azos_sched::scheduler::shim_set_task_filter(owner, Some(SyscallFilter::disabled()));
    const VICTIM: u32 = 0x7c1e_0001;
    FD3_OWNER.store(VICTIM, Ordering::SeqCst);

    // The poller is a kernel task: no user page table.
    let pt = azos_sched::current_user_pt();
    azos_sched::set_current_user_pt(0);
    unsafe { (&mut (*ring).data_buf)[..16].fill(0) };
    let c = unsafe { poll_one(ring, r, sqe(OP_FILE_READ, rw, 0, 16)) };
    let landed = unsafe { (&(*ring).data_buf)[..16].iter().any(|&b| b == b'R') };
    let w = unsafe { poll_one(ring, r, sqe(OP_FILE_WRITE, rw, 0, 8)) };
    let wrote = FILE_WRITES.lock().unwrap_or_else(|e| e.into_inner()).len();
    azos_sched::set_current_user_pt(pt);
    assert_eq!(done(c), (-1, 0), "the poller read a descriptor the owner does not own");
    assert!(!landed, "the victim's bytes reached the owner's window");
    assert_eq!(done(w), (-1, 0), "the poller wrote a descriptor the owner does not own");
    assert_eq!(wrote, 0, "a refused write reached the file");

    // Control: the owner's own descriptor, same poller context.
    FD3_OWNER.store(owner, Ordering::SeqCst);
    azos_sched::set_current_user_pt(0);
    let c = unsafe { poll_one(ring, r, sqe(OP_FILE_READ, rw, 0, 16)) };
    azos_sched::set_current_user_pt(pt);
    assert_eq!(done(c), (16, 0), "the owner's own descriptor was refused");
}

/// `fd_owned_by`: only the stamped owner, no kernel pass, never the vacant
/// marker, never an unowned descriptor.
#[test]
fn fd_owned_by_admits_only_the_stamped_owner() {
    use crate::file_ops::fd_owned_by;
    assert!(fd_owned_by(Some(7), 7, 0));
    assert!(!fd_owned_by(Some(7), 8, 0));
    assert!(!fd_owned_by(None, 7, 0));
    assert!(!fd_owned_by(Some(0), 0, 0), "the vacant marker matched itself");
}

// ── OVSwrap review F4: the I2C payload is read once ───────────────────────

/// The ring page, for the probe below: it plays ring 3 writing its own buffer
/// while the driver runs.
static RACE_RING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// `(register seen first, register seen again)` by the probe.
static REG_SEEN: Mutex<Vec<(u8, u8)>> = Mutex::new(Vec::new());

/// An I2C driver that reads the register byte, lets "ring 3" rewrite the
/// window under it, and reads the register byte again.
fn racing_i2c_write(_bus: u8, _addr: u8, data: &[u8]) -> i32 {
    // Volatile reads: `data` is a shared slice, so the compiler may otherwise
    // reuse the first read for the second and hide exactly what this probes.
    let first = unsafe { core::ptr::read_volatile(data.as_ptr()) };
    let ring = RACE_RING.load(Ordering::SeqCst) as *mut IoRing;
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*ring).data_buf[0]), 0xEE) };
    let again = unsafe { core::ptr::read_volatile(data.as_ptr()) };
    REG_SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((first, again));
    0
}

/// **`OP_I2C_WRITE` hands the driver a copy of its payload, not the ring
/// window.** `data[0]` is the register, and ring 3 maps the window RW: the
/// probe driver reads the register, the window is rewritten (what ring 3 can
/// do on another hart), and the driver reads the register again. Both reads
/// must see the register submitted.
///
/// **Canary (by hand, 2026-10-02).** In `ioring_ops::i2c_write`, pass
/// `core::slice::from_raw_parts(data, len)` to the driver instead of the stack
/// copy: red on "the driver saw the register change under it", `(0x21, 0xee)`.
#[test]
fn an_i2c_write_entry_gives_the_driver_one_stable_copy_of_its_payload() {
    use azos_ipc::cap::targets::I2c;
    struct ProbeGuard;
    impl Drop for ProbeGuard {
        fn drop(&mut self) {
            azos_drv_bus::i2c::set_i2c_write_probe(None);
            RACE_RING.store(0, Ordering::SeqCst);
            REG_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
        }
    }
    let _g = serial();
    let (s, pt) = ring3();
    let (cap, _va, ring) = create(pt);
    let _p = ProbeGuard;
    const BUS: u32 = 1;
    const ADDR: u16 = 0x40;
    grant::<I2c>(s.tid, CapPerms::RW, (BUS << 8) | ADDR as u32);
    RACE_RING.store(ring as usize, Ordering::SeqCst);
    REG_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    azos_drv_bus::i2c::set_i2c_write_probe(Some(racing_i2c_write));
    unsafe { (&mut (*ring).data_buf)[..3].copy_from_slice(&[0x21, 0x10, 0x20]) };
    let mut e = sqe(azos_ipc::io_ring::OP_I2C_WRITE, BUS, 0, 3);
    e.addr = ADDR;
    let (_, c) = unsafe { submit(cap, ring, e) };
    assert_eq!(done(c), (0, 0), "the write did not run");
    let seen = REG_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(seen, vec![(0x21, 0x21)], "the driver saw the register change under it");
}

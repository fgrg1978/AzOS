// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the kernel's io_ring op table (`crates/core/syscall/src/ioring_ops.rs`)
// and the ring handlers in `crates/core/syscall/src/ipc_handlers.rs`.
//
// **What is real here.** The ring's own checks (`crates/core/ipc/src/io_ring.rs`,
// pulled in whole by `shims/ipc`) run against `KERNEL_IORING_OPS`: the
// submitter's filter through the real `SyscallFilter::verdict_for`, the
// owner's real capability table, the real `khost` resolve, mask and interface
// dispatch an `OP_CALL` reaches, the real `motor_host::wheel_speed` (the
// effect gate's seam, the real `motor_set_reporting` with its halt rule from
// `shims/robot`, the real commander table), and the call on the same state
// wherever the two doors must give the same answer. The ring page is mapped by the
// `shm_map_user` stand-in into a real Sv39 table and read back through the
// real `translate_user`.
//
// **What is not.** The sensor is the encoder pair `shims/robot` reports, and
// the PWM and GPIO drivers are the probes in `shims/drivers`.
//
// The ring-level rules against a test table — back-pressure, the refusal flag,
// the message window — are in `crates/core/ipc/src/io_ring.rs`'s own suite.

use super::harness::serial;
use crate::ioring_ops::KERNEL_IORING_OPS;
use crate::ipc_handlers::{sys_ioring_create_typed, sys_ioring_destroy_typed, sys_ioring_submit_typed};
use azos_abi::cap::{CapPerms, ty};
use azos_abi::error::Errno;
use azos_abi::syscall_nr as nr;
use azos_arch_api::PagePerms;
use azos_drv_gpio::gpio::{set_gpio_probe, GpioOp};
use azos_drv_actuator::pwm::{set_pwm_probe, PwmOp};
use azos_ipc::cap::CapTarget;
use azos_ipc::io_ring::{
    CqEntry, IoRing, SqEntry, CQE_F_DURABLE, CQE_F_QUEUED, CQE_F_REFUSED, OP_BUF_REGISTER, OP_BUF_UNREGISTER, OP_FSYNC, OP_NET_RECV,
    OP_NET_SEND, OP_FILE_READ, OP_FILE_WRITE, SQE_F_FIXED,
    OP_NOP, OP_TIMER,
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
    azos_sched::shim_set_brk(0x10_0000);
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

/// Grant `tid` an endpoint capability to the kernel-hosted interface `key` for
/// the resource `badge`, with `perms` as its op classes.
fn grant_dev(tid: u32, key: u16, badge: u32, perms: CapPerms) {
    azos_ipc::endpoint::kernel_endpoint_cap(tid, perms, key, badge).expect("cap table full");
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
///
/// With Kconfig `IORING_ASYNC` every file entry is the worker's and every block
/// entry a queued request, so a submitter that may block gets the worker's
/// turn here, as the kernel's worker task takes it after the wake-up, and the
/// count answered is the completions written in all. An RT submitter (the
/// scene sets its priority) is answered by the submit alone: its hand-off is
/// the test's to run.
unsafe fn submit(cap: u64, ring: *mut IoRing, e: SqEntry) -> (i64, CqEntry) {
    let tail = (*ring).sq_tail.load(Ordering::Acquire);
    (*ring).sq_entries[tail as usize % RING_SQ_SIZE] = e;
    (*ring).sq_tail.store(tail.wrapping_add(1), Ordering::Release);
    let cq = (*ring).cq_tail.load(Ordering::Acquire);
    let mut n = sys_ioring_submit_typed(cap);
    if azos_limits::IORING_ASYNC && n >= 0
        && azos_sched::scheduler::current_task_base_priority() >= azos_sched::RT_PRIORITY_THRESHOLD
    {
        azos_ipc::io_ring::io_ring_worker_pass();
        n = (*ring).cq_tail.load(Ordering::Acquire).wrapping_sub(cq) as i64;
    }
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
    crate::motor_host::set_provider_check(served);
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

/// **The kernel writes the layout version at setup**, readable at
/// `azos_abi::io_ring::VERSION` through the task's own mapping.
///
/// **Canary.** Delete the `version.store(..)` in `io_ring_create`: this goes
/// red (the page is zeroed, so the word reads 0). Store 2, the layout of the
/// device opcodes: red.
#[test]
fn the_kernel_writes_the_layout_version_at_setup() {
    let _g = serial();
    let (_s, pt) = ring3();
    let (cap, va, ring) = create(pt);
    let mut word = [0u8; 4];
    assert!(azos_sched::copy_from_user(word.as_mut_ptr(), va + azos_abi::io_ring::VERSION, 4));
    assert_eq!(u32::from_le_bytes(word), azos_abi::io_ring::IO_RING_VERSION);
    assert_eq!(u32::from_le_bytes(word), 3, "today's layout is version 3 (`OP_CALL`)");
    // The kernel's own view of the same page agrees.
    assert_eq!(unsafe { (*ring).version.load(Ordering::Acquire) }, 3);
    assert_eq!(sys_ioring_destroy_typed(cap), 0);
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

/// **A profile without the `motor` interface refuses the motor entries, and no
/// PWM channel is written**, the endpoints held.
///
/// **Canary.** Drop the `iface_allowed` test from `idl_call`: both wheels
/// are driven.
#[test]
fn a_profile_without_the_motor_interface_refuses_the_motor_entries_and_moves_nothing() {
    let _g = serial();
    let (s, pt) = ring3();
    let l = grant_ep(s.tid, azos_devif::key::MOTOR, 0, CapPerms::RW, 0);
    let r = grant_ep(s.tid, azos_devif::key::MOTOR, 1, CapPerms::RW, 0);
    wheels();
    let (cap, _va, ring) = create(pt);
    azos_sched::scheduler::set_current_syscall_filter(profile(&[nr::SYS_RING_ENTER, nr::SYS_IPC_CALL], false));
    unsafe {
        queue_call(ring, l, 0, &[motor_speed_hdr(), 30], 1);
        queue_call(ring, r, 64, &[motor_speed_hdr(), 30], 2);
    }
    let c = unsafe { submit_queued(cap, ring) };
    let eperm = (Errno::EPERM.to_syscall_ret() as i32, CQE_F_REFUSED);
    assert_eq!(c.iter().map(|c| done(*c)).collect::<Vec<_>>(), vec![eperm, eperm]);
    assert!(pwm_calls().is_empty(), "a denied motor entry wrote {:?}", pwm_calls());
}

// ── A GPIO entry names its controller ─────────────────────────────────────

/// Every op of the expander a GPIO entry reaches, `(pin, level)`.
static EXPANDER_WRITES: Mutex<Vec<(u32, u32)>> = Mutex::new(Vec::new());
/// Every op an entry made on the board controller's stand-in.
static BOARD_OPS: Mutex<Vec<(GpioOp, u32, u32)>> = Mutex::new(Vec::new());

struct RingExpander;

impl azos_drv_gpio::chips::GpioChip for RingExpander {
    fn pins(&self) -> u32 {
        16
    }
    fn read(&self, _pin: u32) -> Result<u32, azos_drv_gpio::chips::Fault> {
        Ok(1)
    }
    fn write(&self, pin: u32, level: u32) -> Result<(), azos_drv_gpio::chips::Fault> {
        EXPANDER_WRITES.lock().unwrap_or_else(|e| e.into_inner()).push((pin, level));
        Ok(())
    }
    fn set_dir(&self, _pin: u32, _dir: azos_drv_gpio::gpio::GpioDir) -> Result<(), azos_drv_gpio::chips::Fault> {
        Ok(())
    }
    fn may_sleep(&self) -> bool {
        RING_EXPANDER_SLEEPS.load(Ordering::SeqCst)
    }
}

static RING_EXPANDER: RingExpander = RingExpander;
/// The expander models a part behind a bus that sleeps (an I2C one on a
/// DesignWare controller).
static RING_EXPANDER_SLEEPS: AtomicBool = AtomicBool::new(false);

fn board_probe(op: GpioOp, pin: u32, arg: u32) -> i32 {
    BOARD_OPS.lock().unwrap_or_else(|e| e.into_inner()).push((op, pin, arg));
    0
}

/// **A GPIO entry names its controller**: a `Gpio::write` entry on the
/// endpoint whose badge is pin 3 of controller 1 drives the expander's pin 3,
/// and the board's controller sees nothing; a pin past the expander's last is
/// answered `BAD_ARGUMENT`, and with the expander unbound `NO_RESOURCE`,
/// neither reaching a driver.
///
/// **Canary.** Map every `GpioPin::of` refusal to `FAULT` in `devices.rs`:
/// the unbound entry answers `FAULT`.
#[test]
fn a_gpio_entry_on_controller_1_drives_the_expanders_pin_and_not_the_boards() {
    let _g = serial();
    let (s, pt) = ring3();
    EXPANDER_WRITES.lock().unwrap().clear();
    BOARD_OPS.lock().unwrap().clear();
    set_gpio_probe(Some(board_probe));
    let dev = super::harness::GPIO_EXPANDER_DEV;
    assert_eq!(azos_drv_gpio::chips::register(dev, &RING_EXPANDER), Ok(1));
    let (cap, _va, ring) = create(pt);
    let pin3 = grant_ep(s.tid, azos_devif::key::GPIO, azos_devif::gpio::badge(1, 3), CapPerms::RW, 0);
    let past = grant_ep(s.tid, azos_devif::key::GPIO, azos_devif::gpio::badge(1, 16), CapPerms::RW, 0);
    let write = |ep: u32| unsafe {
        queue_call(ring, ep, 0, &[gpio_hdr(azos_devif::GpioIdl::OP_WRITE), 1], 1);
        let c = submit_queued(cap, ring);
        assert_eq!(done(c[0]), (0, 0), "the ring refused a held GPIO entry");
        window(ring, 0)[1] as u32
    };
    use azos_devif::outcome::{BAD_ARGUMENT, NO_RESOURCE, OK};
    assert_eq!(write(pin3), OK);
    assert_eq!(write(past), BAD_ARGUMENT);
    let _ = azos_drv_gpio::chips::unregister(dev, &mut || false);
    assert_eq!(write(pin3), NO_RESOURCE);
    assert_eq!(*EXPANDER_WRITES.lock().unwrap(), vec![(3, 1)]);
    assert_eq!(*BOARD_OPS.lock().unwrap(), vec![], "the board's controller saw a controller-1 entry");
}

fn gpio_hdr(op: u16) -> u64 {
    use azos_devif::GpioIdl as G;
    azos_idl::header(G::ID, G::LEVEL, op)
}

// ── The effect gate on the ring ─────────────────────────────────────────────
//
// A stand-in for the kernel's gate (`azos_actuation::effect_gate`, covered by
// `actuation-tests`), as `motor_guards.rs` installs one for the typed op: it
// keeps what it was asked to issue and, when told to, refuses a motion op as
// the real one refuses it (a full recorder ring, a held wheel, a deadline the
// server cannot meet). A stop is never refused.

static RING_GATE_SEEN: Mutex<Vec<(u32, u32, u32, bool)>> = Mutex::new(Vec::new());
static RING_GATE_REFUSES: AtomicBool = AtomicBool::new(false);

fn ring_gate(e: &crate::motor_host::MotorEffect, op: &mut dyn FnMut() -> bool) -> bool {
    RING_GATE_SEEN.lock().unwrap_or_else(|x| x.into_inner()).push((e.wheel, e.tid, e.pct, e.toward_safe));
    if RING_GATE_REFUSES.load(Ordering::SeqCst) && !e.toward_safe {
        return false;
    }
    op();
    true
}

fn ring_gate_seen() -> Vec<(u32, u32, u32, bool)> {
    core::mem::take(&mut *RING_GATE_SEEN.lock().unwrap_or_else(|x| x.into_inner()))
}

/// What no gate does: run the op. Put back when a test here ends.
fn no_gate(_e: &crate::motor_host::MotorEffect, op: &mut dyn FnMut() -> bool) -> bool {
    op();
    true
}

/// A kernel whose robot provider owns the motor kind. Put back when a test
/// here ends.
fn served(_e: &crate::motor_host::MotorEffect) -> bool {
    true
}

/// A kernel no provider gives wheels.
fn unserved(_e: &crate::motor_host::MotorEffect) -> bool {
    false
}

struct RingGate;

impl Drop for RingGate {
    fn drop(&mut self) {
        crate::motor_host::set_provider_check(served);
        crate::motor_host::set_effect_gate(no_gate);
        RING_GATE_REFUSES.store(false, Ordering::SeqCst);
    }
}

/// **No provider, no wheel, on the ring too.** On an image whose providers
/// own no motor kind a motor entry is answered `UNSUPPORTED`, reaches neither
/// the effect gate nor a wheel, and names no commander.
///
/// **Canary.** Answer `Unissued::NoDevice` with `REFUSED` in
/// `Unissued::outcome`: the entry answers `REFUSED`.
#[test]
fn a_motor_entry_on_an_image_without_wheels_answers_unsupported() {
    let _g = serial();
    let (s, pt) = ring3();
    let l = grant_ep(s.tid, azos_devif::key::MOTOR, 0, CapPerms::RW, 0);
    wheels();
    let (cap, _va, ring) = create(pt);
    let _gate = RingGate;
    ring_gate_seen();
    crate::motor_host::set_effect_gate(ring_gate);
    crate::motor_host::set_provider_check(unserved);

    unsafe { queue_call(ring, l, 0, &[motor_speed_hdr(), 30], 1) };
    let c = unsafe { submit_queued(cap, ring) };
    assert_eq!(done(c[0]), (0, 0));
    assert_eq!(unsafe { window(ring, 0) }[1], azos_devif::outcome::UNSUPPORTED as u64, "a motor entry with no wheel");
    assert!(ring_gate_seen().is_empty(), "an unserved entry was put to the effect gate");
    assert!(pwm_calls().is_empty(), "an unserved entry wrote {:?}", pwm_calls());
}

/// **A motor entry is the typed `speed` op, effect gate and commander
/// included.** Each wheel's command reaches the effect gate as the RING
/// OWNER's (its record, its hold, its deadline watch and provenance are
/// that task's) before it reaches the wheel, and a wheel left turning names
/// the owner as its commander, so the owner's death stops it (Kconfig
/// `MOTOR_COMMANDER_EXIT_STOP`). A motion entry the gate refuses writes
/// nothing and is answered `REFUSED`, as the call is; a stop is never refused
/// and clears the commander.
///
/// **Canary.** Make `MotorServer::speed` call `motor_set_reporting` directly
/// in place of `wheel_speed`: the gate sees nothing, the refused entry drives
/// both wheels, and no wheel names a commander.
#[test]
fn a_motor_entry_goes_through_the_effect_gate_and_names_its_owner_as_commander() {
    let _g = serial();
    let (s, pt) = ring3();
    let eps = [
        grant_ep(s.tid, azos_devif::key::MOTOR, 0, CapPerms::RW, 0),
        grant_ep(s.tid, azos_devif::key::MOTOR, 1, CapPerms::RW, 0),
    ];
    wheels();
    let (cap, _va, ring) = create(pt);
    let _gate = RingGate;
    ring_gate_seen();
    crate::motor_host::set_effect_gate(ring_gate);
    let both = |l: u64, r: u64| unsafe {
        queue_call(ring, eps[0], 0, &[motor_speed_hdr(), l], 1);
        queue_call(ring, eps[1], 64, &[motor_speed_hdr(), r], 2);
        let c = submit_queued(cap, ring);
        assert_eq!(c.iter().map(|c| done(*c)).collect::<Vec<_>>(), vec![(0, 0), (0, 0)]);
        (window(ring, 0)[1] as u32, window(ring, 64)[1] as u32)
    };
    use azos_devif::outcome::{OK, REFUSED};

    assert_eq!(both(30, 40), (OK, OK));
    assert_eq!(ring_gate_seen(), vec![(0, s.tid, 30, false), (1, s.tid, 40, false)],
               "the entry's commands did not reach the effect gate as the owner's");
    assert_eq!(pwm_calls(), vec![(PwmOp::SetDutyPct, CH[0], 30), (PwmOp::SetDutyPct, CH[1], 40)]);
    for id in 0..2 {
        assert_eq!(crate::motor_commander::commander(id), commander_of(s.tid),
                   "wheel {id} left turning names no commander: the owner's exit would not stop it");
    }

    RING_GATE_REFUSES.store(true, Ordering::SeqCst);
    clear_pwm_calls();
    assert_eq!(both(60, 60), (REFUSED, REFUSED), "a refused motion entry was not answered REFUSED");
    assert!(pwm_calls().is_empty(), "a motion entry the gate refused wrote {:?}", pwm_calls());
    assert_eq!(ring_gate_seen().len(), 2);

    assert_eq!(both(0, 0), (OK, OK), "a stop entry was refused");
    assert_eq!(ring_gate_seen(), vec![(0, s.tid, 0, true), (1, s.tid, 0, true)]);
    assert_eq!(pwm_calls(), vec![(PwmOp::SetDutyPct, CH[0], 0), (PwmOp::SetDutyPct, CH[1], 0)]);
    for id in 0..2 {
        assert_eq!(crate::motor_commander::commander(id), 0, "a stopped wheel {id} still names a commander");
    }
}

/// **Containment refuses the PWM entry's act and writes nothing; a read on
/// the same ring keeps running.** The act is answered `DENIED` by the
/// interface, as the call is answered while contained; the ring itself
/// refuses nothing.
///
/// **Canary.** Test `holds` in place of `allows` in `Caller::gate`: the
/// contained entry writes duty 40.
#[test]
fn containment_refuses_the_pwm_entry_and_keeps_reads_running() {
    let _g = serial();
    let (s, pt) = ring3();
    let pwm = grant_ep(s.tid, azos_devif::key::PWM, FREE_CH, CapPerms::RW, 0);
    let enc = grant_ep(s.tid, azos_devif::key::SENSOR, SENSOR_TYPE_ENCODER as u32, CapPerms::READ, 0);
    set_pwm_probe(Some(pwm_probe));
    clear_pwm_calls();
    let (cap, _va, ring) = create(pt);
    let duty = {
        use azos_devif::PwmIdl as P;
        azos_idl::header(P::ID, P::LEVEL, P::OP_SET_DUTY_PCT)
    };

    azos_ipc::cap::degraded_set(true);
    unsafe {
        queue_call(ring, pwm, 0, &[duty, 40], 1);
        queue_call(ring, enc, 64, &[sensor_read_hdr()], 2);
    }
    let c = unsafe { submit_queued(cap, ring) };
    assert_eq!(c.iter().map(|c| done(*c)).collect::<Vec<_>>(), vec![(0, 0), (0, 0)], "the ring refused while contained");
    assert_eq!(unsafe { window(ring, 0) }[1], azos_devif::outcome::DENIED as u64);
    assert!(pwm_calls().is_empty(), "a contained entry wrote {:?}", pwm_calls());
    assert_eq!(unsafe { window(ring, 64) }[1], azos_devif::outcome::OK as u64, "a read on the same ring");

    azos_ipc::cap::degraded_set(false);
    unsafe { queue_call(ring, pwm, 0, &[duty, 40], 1) };
    let c = unsafe { submit_queued(cap, ring) };
    assert_eq!(done(c[0]), (0, 0));
    assert_ne!(unsafe { window(ring, 0) }[1], azos_devif::outcome::DENIED as u64, "released, the entry runs");
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
    fn open_at(&self, _root: &[u8], _path: &[u8], _flags: u32) -> i64 { -1 }
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
    assert_eq!(typed_seen(), vec![(ty::FILE.denial_code(), CapError::MissingPerms.code())]);
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

/// **K1: an `OP_FSYNC` entry is `NODE_FSYNC` below the trap, without
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
    assert_eq!(typed_seen(), vec![(ty::FILE.denial_code(), CapError::Stale.code())]);

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
/// completes it `CQE_F_QUEUED`. A task outside the RT band runs it inline, or
/// (Kconfig `IORING_ASYNC`) hands it to the worker too, which `submit` runs.
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
    // Outside the RT band: inline, or the worker's turn that `submit` takes.
    let (n, c) = unsafe { submit(cap, ring, sqe(OP_FILE_WRITE, rw, 0, 8)) };
    assert_eq!((n, done(c)), (1, (8, CQE_F_QUEUED)));
}

/// **K1: `OP_NET_SEND` is `NODE_SEND` below the trap, without the
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
    assert_eq!(typed_seen(), vec![(ty::SOCKET.denial_code(), CapError::MissingPerms.code())]);
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_NET_SEND, 0xDEAD_0000, 0, 4)) };
    assert_eq!(done(c), (Errno::ECAPSTALE.to_syscall_ret() as i32, CQE_F_REFUSED));
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_NET_SEND, stranger, 0, 4)) };
    assert_eq!(done(c), (crate::handlers::E_PERM as i32, CQE_F_REFUSED), "a stranger's socket was reached");
    let (n, c) = unsafe { submit(cap, ring, sqe(OP_NET_SEND, wo, 0, 4)) };
    assert_eq!((n, done(c)), (1, (-1, 0)), "the owner's socket was not reached, or the answer was flagged");
    azos_net::socket_close(mine);
    azos_net::socket_close(theirs);
}

/// **`OP_NET_RECV` is `NODE_RECV` below the trap, without the wait.** The SQE
/// names a `Cap<Socket>` in the owner's table: a WRITE-only handle is refused
/// `-ECAPPERMS` and recorded as a Socket denial, a forged one `-ECAPSTALE`; a
/// READ handle on a socket another task owns is refused (the owner stamp, as
/// `socket_access_ok`); a READ handle on the owner's own socket reaches
/// `socket_recv` and answers its result unflagged, `-1` while the datagram
/// socket is unbound and `-EAGAIN` once it is bound with nothing queued: it
/// never waits.
///
/// **Canaries.** Resolve with `WRITE`: the WRITE handle reaches the socket.
/// Drop the owner-stamp check: the stranger's socket answers -1, unrefused.
#[test]
fn a_net_recv_entry_resolves_the_owners_socket_cap_and_never_waits() {
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
    let stranger = grant::<Socket>(s.tid, CapPerms::READ, theirs as u32) as u32;

    let (_, c) = unsafe { submit(cap, ring, sqe(OP_NET_RECV, wo, 0, 4)) };
    assert_eq!(done(c), (Errno::ECAPPERMS.to_syscall_ret() as i32, CQE_F_REFUSED));
    assert_eq!(typed_seen(), vec![(ty::SOCKET.denial_code(), CapError::MissingPerms.code())]);
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_NET_RECV, 0xDEAD_0000, 0, 4)) };
    assert_eq!(done(c), (Errno::ECAPSTALE.to_syscall_ret() as i32, CQE_F_REFUSED));
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_NET_RECV, stranger, 0, 4)) };
    assert_eq!(done(c), (crate::handlers::E_PERM as i32, CQE_F_REFUSED), "a stranger's socket was reached");
    azos_net::shim_arm_net_poll(true);
    let (n, c) = unsafe { submit(cap, ring, sqe(OP_NET_RECV, ro, 0, 4)) };
    assert_eq!((n, done(c)), (1, (-1, 0)), "an unbound datagram socket cannot receive; the answer is not a refusal");
    let local = azos_net::socket::SockAddr { family: 2, port: 7771, addr: [0; 4] };
    assert_eq!(azos_net::socket::socket_bind(mine, &local), 0);
    // No net-poll task here (the shim says so), so the entry drains the NIC
    // itself, once per look, as the typed call does.
    azos_net::shim_arm_net_poll(true);
    let (n, c) = unsafe { submit(cap, ring, sqe(OP_NET_RECV, ro, 0, 4)) };
    assert_eq!((n, done(c)), (1, (-11, 0)), "nothing queued answers -EAGAIN at once");
    assert_eq!(azos_net::shim_net_polls(), Some(1), "the receive did not poll the NIC as the typed call does");
    azos_net::shim_arm_net_poll(false);
    // An empty window is `-1`, as the typed call's `len == 0`.
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_NET_RECV, ro, 0, 0)) };
    assert_eq!(done(c), (-1, 0));
    azos_net::socket_close(mine);
    azos_net::socket_close(theirs);
}

/// The reference count `shm` (a raw handle) holds on its object, and the
/// object's packed reference.
fn shm_refs(tid: u32, shm: u32) -> (u32, u32) {
    use azos_ipc::cap::{targets::Shm, Cap};
    let cap: Cap<Shm> = Cap::from_raw(azos_abi::cap::CapHandle::from_raw(shm));
    let r = azos_ipc::cap_store::with_table(tid, |t| t.get_op(cap, CapPerms::READ, 0)).unwrap().expect("live shm");
    let (_, refs, _) = azos_ipc::memobj::memobj_info(azos_ipc::cap::objref::SHM.idx(r)).expect("live object");
    (r, refs)
}

fn buf_entry(opcode: u16, shm: u32, offset: u32, len: u32, slot: u16) -> SqEntry {
    SqEntry { reg: slot, ..sqe(opcode, shm, offset, len) }
}

/// **A registered buffer is a kernel pin on a range of an object the owner
/// maps, and nothing else.** Refused: an object the owner does not map, a
/// capability without `MAP`/`WRITE` (recorded as a Shm denial), a range past
/// the object, an object whose frames a clone shares. Accepted: the range
/// registers (the object's reference count rises by ONE, the pin; no object
/// table slot is taken), a fixed file read lands in the pinned frames at the
/// buffer's offset, where the owner's own mapping reads it, and the pin goes
/// back with an unregister and with the ring's destruction.
///
/// **Canaries.** Skip `memobj_frames_pin` in `buf_pin`: the reference count
/// does not rise. Skip the mapping test: the unmapped registration succeeds.
/// Skip the copy-on-write test: the shared object registers.
#[test]
fn a_registered_buffer_pins_a_range_of_an_object_the_owner_maps() {
    use azos_ipc::cap::targets::{File, Shm};
    use azos_ipc::cap::CapError;
    let _g = serial();
    let (s, pt) = ring3();
    let _f = file_scene();
    let (cap, _va, ring) = create(pt);
    let rd = grant::<File>(s.tid, CapPerms::READ, 3) as u32;
    let shm = crate::ipc_handlers::sys_shm_create_typed(1, 1);
    assert!(shm > 0, "shm create returned {shm}");
    let shm = shm as u32;
    let (r, base_refs) = shm_refs(s.tid, shm);
    let einval = (Errno::EINVAL.to_syscall_ret() as i32, CQE_F_REFUSED);

    // Not mapped by the owner: refused, nothing pinned.
    let (_, c) = unsafe { submit(cap, ring, buf_entry(OP_BUF_REGISTER, shm, 64, 256, 1)) };
    assert_eq!(done(c), einval, "an object the owner does not map was registered");
    assert_eq!(shm_refs(s.tid, shm).1, base_refs);

    let map = crate::ipc_handlers::sys_shm_map_typed(u64::from(shm), 0);
    assert!(map > 0, "map returned {map}");
    let map = map as usize;
    let refs_mapped = shm_refs(s.tid, shm).1;

    // A capability that may not map or write (an attenuated READ handle).
    let weak = grant::<Shm>(s.tid, CapPerms::READ, r) as u32;
    let (_, c) = unsafe { submit(cap, ring, buf_entry(OP_BUF_REGISTER, weak, 64, 256, 1)) };
    assert_eq!(done(c), (Errno::ECAPPERMS.to_syscall_ret() as i32, CQE_F_REFUSED));
    assert_eq!(typed_seen(), vec![(ty::SHM.denial_code(), CapError::MissingPerms.code())]);
    // A range past the object, an empty one, and a slot past the table.
    for (off, len, slot) in [(4000u32, 200u32, 1u16), (0, 0, 1), (u32::MAX, u32::MAX, 1), (0, 64, 4000)] {
        let (_, c) = unsafe { submit(cap, ring, buf_entry(OP_BUF_REGISTER, shm, off, len, slot)) };
        assert_eq!(done(c), einval, "range {off}+{len} slot {slot}");
    }
    assert_eq!(shm_refs(s.tid, shm).1, refs_mapped, "a refused registration kept its pin");

    // The registration: one more reference, the pin.
    let (n, c) = unsafe { submit(cap, ring, buf_entry(OP_BUF_REGISTER, shm, 64, 256, 1)) };
    assert_eq!((n, done(c)), (1, (0, 0)));
    assert_eq!(shm_refs(s.tid, shm).1, refs_mapped + 1, "the registration did not pin the object");

    // A fixed file read lands in the pinned frame at buffer offset 8 = object offset 72.
    let fixed_read = SqEntry { flags: SQE_F_FIXED, reg: 1, ..sqe(OP_FILE_READ, rd, 8, 16) };
    let (_, c) = unsafe { submit(cap, ring, fixed_read) };
    assert_eq!(done(c), (16, 0));
    let phys = azos_mm::vmm::translate_user(pt, map + 72, false).expect("the owner's mapping") as *const u8;
    assert!(unsafe { core::slice::from_raw_parts(phys, 16) }.iter().all(|&b| b == b'R'), "the read missed the pinned range");
    assert!(unsafe { core::slice::from_raw_parts(phys.sub(8), 8) }.iter().all(|&b| b == 0), "the read started early");
    assert!(unsafe { (&(*ring).data_buf)[..16].iter().all(|&b| b == 0) }, "a fixed read wrote the data buffer");
    // One byte past the buffer is refused.
    let past = SqEntry { flags: SQE_F_FIXED, reg: 1, ..sqe(OP_FILE_READ, rd, 249, 8) };
    let (_, c) = unsafe { submit(cap, ring, past) };
    assert_eq!(done(c), einval);

    // Unregister gives the pin back; the slot is then empty.
    let (_, c) = unsafe { submit(cap, ring, buf_entry(OP_BUF_UNREGISTER, 0, 0, 0, 1)) };
    assert_eq!(done(c), (0, 0));
    assert_eq!(shm_refs(s.tid, shm).1, refs_mapped);
    let (_, c) = unsafe { submit(cap, ring, buf_entry(OP_BUF_UNREGISTER, 0, 0, 0, 1)) };
    assert_eq!(done(c), einval);

    // Destroying the ring gives back what it still holds.
    let (_, c) = unsafe { submit(cap, ring, buf_entry(OP_BUF_REGISTER, shm, 0, 128, 0)) };
    assert_eq!(done(c), (0, 0));
    assert_eq!(shm_refs(s.tid, shm).1, refs_mapped + 1);
    assert_eq!(sys_ioring_destroy_typed(cap), 0);
    assert_eq!(shm_refs(s.tid, shm).1, refs_mapped, "destroying the ring left the pin");
    azos_ipc::memobj::memobj_release_all(s.tid);
}

/// **A pin does not outlive the owner's mapping.** The owner registers a range,
/// releases the object (its mapping goes), and every fixed entry on the slot is
/// refused `-EBUSY`, a send included; the slot can still be unregistered, which
/// gives the kernel's reference back.
///
/// **Canary.** Drop the mapping test from `buf_usable`: the send completes.
#[test]
fn a_pin_is_refused_once_the_owner_no_longer_maps_the_object() {
    let _g = serial();
    let (s, pt) = ring3();
    let (cap, _va, ring) = create(pt);
    let shm = crate::ipc_handlers::sys_shm_create_typed(1, 1);
    assert!(shm > 0);
    let shm = shm as u32;
    assert!(crate::ipc_handlers::sys_shm_map_typed(u64::from(shm), 0) > 0);
    let (_, c) = unsafe { submit(cap, ring, buf_entry(OP_BUF_REGISTER, shm, 0, 64, 0)) };
    assert_eq!(done(c), (0, 0));
    let (r, _) = shm_refs(s.tid, shm);
    assert_eq!(crate::ipc_handlers::sys_shm_release_typed(u64::from(shm)), 0);
    let busy = (Errno::EBUSY.to_syscall_ret() as i32, CQE_F_REFUSED);
    for op in [OP_NET_RECV, OP_NET_SEND, OP_FILE_READ, OP_FILE_WRITE] {
        let e = SqEntry { flags: SQE_F_FIXED, reg: 0, ..sqe(op, 0xDEAD_0000, 0, 4) };
        let (_, c) = unsafe { submit(cap, ring, e) };
        assert_eq!(done(c), busy, "opcode {op}");
    }
    let (_, c) = unsafe { submit(cap, ring, buf_entry(OP_BUF_UNREGISTER, 0, 0, 0, 0)) };
    assert_eq!(done(c), (0, 0));
    assert!(azos_ipc::memobj::memobj_info(azos_ipc::cap::objref::SHM.idx(r)).is_none(), "the pin kept the released object alive");
    assert_eq!(sys_ioring_destroy_typed(cap), 0);
    azos_ipc::memobj::memobj_release_all(s.tid);
}

/// **A clone that shares a frame refuses the pin, and a pin keeps any later clone
/// from sharing.** The owner maps the object read-only (so a snapshot may share
/// its frames lazily), clones it, and the registration is refused `-EBUSY`: a
/// receive into it would write the clone's memory. Once registered, the kernel
/// may write the frames whatever the mapping says, so a clone copies them.
#[test]
fn a_shared_object_is_not_pinned_and_a_pin_keeps_a_clone_from_sharing() {
    use azos_ipc::memobj::{memobj_clone, MemPerms};
    let _g = serial();
    let (s, pt) = ring3();
    let (cap, _va, ring) = create(pt);
    let busy = (Errno::EBUSY.to_syscall_ret() as i32, CQE_F_REFUSED);
    for registered_first in [false, true] {
        let shm = crate::ipc_handlers::sys_shm_create_typed(1, 1);
        assert!(shm > 0);
        let shm = shm as u32;
        assert!(crate::ipc_handlers::sys_shm_map_typed(u64::from(shm), 0) > 0);
        let (r, _) = shm_refs(s.tid, shm);
        if registered_first {
            let (_, c) = unsafe { submit(cap, ring, buf_entry(OP_BUF_REGISTER, shm, 0, 64, 0)) };
            assert_eq!(done(c), (0, 0));
        }
        // Read-only mapping: nobody can change the bytes under a lazy share.
        assert_eq!(crate::ipc_handlers::sys_shm_map_typed(u64::from(shm), azos_abi::syscall_nr::SHM_MAP_OP_PROTECT), 0);
        let clone = memobj_clone(s.tid, r, s.tid, MemPerms::ReadWrite).expect("clone");
        let shared = azos_ipc::memobj::memobj_describe_ref(r).unwrap().cow_shared != 0;
        assert_eq!(shared, !registered_first, "a clone shares only frames the kernel cannot write");
        if registered_first {
            let (_, c) = unsafe { submit(cap, ring, buf_entry(OP_BUF_UNREGISTER, 0, 0, 0, 0)) };
            assert_eq!(done(c), (0, 0));
        } else {
            let (_, c) = unsafe { submit(cap, ring, buf_entry(OP_BUF_REGISTER, shm, 0, 64, 0)) };
            assert_eq!(done(c), busy, "a shared object was pinned");
        }
        let _ = clone;
    }
    assert_eq!(sys_ioring_destroy_typed(cap), 0);
    azos_ipc::memobj::memobj_release_all(s.tid);
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
    // Under IORING_ASYNC the poller hands a file entry to the worker, a kernel
    // task as the poller is: it runs the entry with the owner's authority.
    if azos_limits::IORING_ASYNC {
        azos_ipc::io_ring::io_ring_worker_pass();
    }
    azos_sched::set_current_task_tid(owner);
    if azos_limits::IORING_ASYNC {
        assert!(matches!(p, azos_ipc::io_ring::SqpollPass::Done { .. }), "{p:?}");
    } else {
        assert!(matches!(p, azos_ipc::io_ring::SqpollPass::Done { ran: 1, .. }), "{p:?}");
    }
    let c = (*ring).cq_entries[cq as usize % RING_CQ_SIZE];
    (*ring).cq_head.store((*ring).cq_tail.load(Ordering::Acquire), Ordering::Release);
    c
}

/// **A poller pass is decided by the OWNER's seccomp profile**, read from the
/// owner's slot, not by the poller's (a kernel task, unfiltered): a profile
/// without `NODE_READ` refuses the owner's granted file read through
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

    azos_sched::scheduler::shim_set_task_filter(owner, Some(profile(&[nr::SYS_RING_ENTER], false)));
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
    // The poller's refusal of the owner's entry (a call on a handle the owner
    // does not hold): recorded, as the same record.
    let c = unsafe { poll_call(ring, r, 0x77, &[sensor_read_hdr()]) };
    assert_eq!(done(c), (Errno::ECAPPERMS.to_syscall_ret() as i32, CQE_F_REFUSED));
    assert_eq!(
        typed_seen(),
        vec![
            (ty::FILE.denial_code(), CapError::Stale.code()),
            (ty::ENDPOINT.denial_code(), CapError::Stale.code()),
        ]
    );
    // Two more of the owner's own: its bound of four is spent.
    for _ in 0..2 {
        let _ = crate::handlers::sys_file_read_typed(0, 0, 0);
    }
    assert_eq!(typed_seen().len(), 4);
    // The poller refuses the owner's entry again: suppressed, like the owner's
    // fifth refusal.
    let c = unsafe { poll_call(ring, r, 0x77, &[sensor_read_hdr()]) };
    assert_eq!(done(c).1, CQE_F_REFUSED);
    assert_eq!(typed_seen().len(), 4, "the poller's refusal was charged to the poller, not the owner");
}

/// **The actuation gate per entry under SQPOLL.** Motor entries the poller
/// runs under a latched e-stop hold both wheels at duty 0 and are answered
/// `REFUSED`, as the submitted entries are; released, the poller's entry is
/// the OWNER's command at the effect gate.
#[test]
fn a_poller_motor_entry_under_a_latched_estop_holds_both_wheels_at_duty_zero() {
    let _g = serial();
    let (_s, _p, _f, owner, ring, r) = polled_ring();
    azos_sched::scheduler::shim_set_task_filter(owner, Some(SyscallFilter::disabled()));
    let eps = [
        grant_ep(owner, azos_devif::key::MOTOR, 0, CapPerms::RW, 0),
        grant_ep(owner, azos_devif::key::MOTOR, 1, CapPerms::RW, 0),
    ];
    wheels();
    let _gate = RingGate;
    ring_gate_seen();
    crate::motor_host::set_effect_gate(ring_gate);
    ESTOP.store(true, Ordering::SeqCst);
    for ep in eps {
        let c = unsafe { poll_call(ring, r, ep, &[motor_speed_hdr(), 50]) };
        assert_eq!(done(c), (0, 0));
        assert_eq!(unsafe { window(ring, 0) }[1], azos_devif::outcome::REFUSED as u64);
    }
    let duties: Vec<u32> = pwm_calls().iter().filter(|c| c.0 == PwmOp::SetDutyPct).map(|c| c.2).collect();
    assert_eq!(duties, vec![0, 0], "a wheel moved under a latched e-stop");
    ESTOP.store(false, Ordering::SeqCst);
    let c = unsafe { poll_call(ring, r, eps[0], &[motor_speed_hdr(), 50]) };
    assert_eq!(done(c), (0, 0));
    assert_eq!(ring_gate_seen(), vec![(0, owner, 50, false)], "the poller's entry was not the owner's command");
    assert_eq!(crate::motor_commander::commander(0), commander_of(owner), "the poller's command named another commander");
}

/// The commander a wheel driven by `tid` names: `tid`, or nobody when the
/// kernel keeps no commanders (Kconfig `MOTOR_COMMANDER_EXIT_STOP` off), so
/// the assertion discriminates in either build.
fn commander_of(tid: u32) -> u32 {
    if azos_limits::MOTOR_COMMANDER_EXIT_STOP { tid } else { 0 }
}

/// [`poll_one`] for an `OP_CALL` of `words` on `ep`, in the window at 0.
unsafe fn poll_call(ring: *mut IoRing, r: u32, ep: u32, words: &[u64]) -> CqEntry {
    put_window(ring, 0, words);
    poll_one(ring, r, sqe(azos_ipc::io_ring::OP_CALL, ep, 0, words.len() as u32))
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

/// **An op mask gates the ring's own ops and the entries it runs for its
/// owner.** `SYS_IORING_SUBMIT` is the `WRITE` class of the ring (it moves
/// data) and the destroy is `CTL`; a file entry resolves the owner's handle as
/// the op it is (`NODE_READ` is `READ`, `NODE_WRITE` is `WRITE`). A refusal of
/// an entry completes it `-ECAPPERMS` with `CQE_F_REFUSED`, as an unmasked
/// handle without the right does.
///
/// **Canary.** Resolve `file_io` with `get` (no op): the allowed read below
/// completes `-ECAPPERMS`. Resolve the submit with `get_uncontained`: the
/// `WRITE` copy's submit is refused.
#[test]
fn an_op_mask_gates_the_ring_ops_and_its_entries() {
    use super::harness::{classes, op_masked};
    use azos_abi::invoke::{CLASS_CTL, CLASS_READ, CLASS_WRITE};
    use azos_ipc::cap::targets::File;
    let _g = serial();
    let (s, pt) = ring3();
    let _f = file_scene();
    let (cap, _va, ring) = create(pt);
    let denied = Errno::ECAPPERMS.to_syscall_ret();

    // The ring's own ops.
    let (wr_ring, rd_ring, ctl_ring) = (
        op_masked(s.tid, cap, classes(&[CLASS_WRITE])),
        op_masked(s.tid, cap, classes(&[CLASS_READ])),
        op_masked(s.tid, cap, classes(&[CLASS_CTL])),
    );
    assert_eq!(sys_ioring_submit_typed(wr_ring), 0, "the WRITE copy submits an empty queue");
    assert_eq!(sys_ioring_submit_typed(rd_ring), denied);
    assert_eq!(sys_ioring_submit_typed(ctl_ring), denied);

    // The entries, through the unmasked ring.
    let rw = grant::<File>(s.tid, CapPerms::RW, 3);
    let (rd_file, wr_file) = (
        op_masked(s.tid, rw, classes(&[CLASS_READ])),
        op_masked(s.tid, rw, classes(&[CLASS_WRITE])),
    );
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_FILE_READ, rd_file as u32, 0, 16)) };
    assert_eq!(done(c), (16, 0), "a READ entry through the READ copy");
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_FILE_READ, wr_file as u32, 0, 16)) };
    assert_eq!(done(c), (denied as i32, CQE_F_REFUSED), "a READ entry through the WRITE copy");
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_FILE_WRITE, wr_file as u32, 0, 8)) };
    assert_eq!(done(c), (8, CQE_F_QUEUED), "a WRITE entry through the WRITE copy");
    let (_, c) = unsafe { submit(cap, ring, sqe(OP_FILE_WRITE, rd_file as u32, 0, 8)) };
    assert_eq!(done(c), (denied as i32, CQE_F_REFUSED), "a WRITE entry through the READ copy");

    // The destroy: CTL.
    assert_eq!(sys_ioring_destroy_typed(wr_ring), denied);
    assert_eq!(sys_ioring_destroy_typed(rd_ring), denied);
    assert_eq!(sys_ioring_destroy_typed(ctl_ring), 0);
}

// ── Queued block requests (Kconfig IORING_ASYNC) ──────────────────────────
//
// The kernel's `block_start` / `block_poll` / `block_orphan` / `block_service`
// against the real partition table and the request-layer stand-in of
// `shims/drivers` (`set_raw_layer`): a request lends the layer a buffer and the
// device touches it only when somebody waits for it, as the real layer does.

mod queued_blocks {
    use super::*;
    use azos_drv_block::blkdev::{raw_queued, set_blk_probe, set_raw_layer};
    use azos_drv_block::partition::{self, Partition, Scheme, Table, MAX_PARTS};
    use azos_ipc::io_ring::{BlockStart, OP_BLOCK_READ, OP_BLOCK_WRITE};

    /// Every request that reached the device: `(write, absolute sector, count, bytes of a write)`.
    static DEVICE: Mutex<Vec<(bool, u64, u32, Vec<u8>)>> = Mutex::new(Vec::new());
    /// The device fails every request.
    static FAILS: AtomicBool = AtomicBool::new(false);
    /// Sectors reported to the write observer.
    static OBSERVED: Mutex<Vec<(u64, u32)>> = Mutex::new(Vec::new());

    fn probe(write: bool, sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
        DEVICE.lock().unwrap_or_else(|e| e.into_inner()).push((write, sector, count, if write { buf.to_vec() } else { Vec::new() }));
        if FAILS.load(Ordering::SeqCst) {
            return Err(());
        }
        if !write {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (sector as u8).wrapping_add((i / 512) as u8);
            }
        }
        Ok(())
    }

    fn observer(sector: u64, count: u32) {
        OBSERVED.lock().unwrap_or_else(|e| e.into_inner()).push((sector, count));
    }

    fn device() -> Vec<(bool, u64, u32, Vec<u8>)> {
        DEVICE.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Partition 0 = LBA 2048 + 4096 (badge 1), partition 1 = LBA 8192 + 1024 (badge 2);
    /// a request layer of 8-sector commands; the probe armed.
    fn scene() {
        partition::reset_for_tests();
        let none = Partition { start: 0, sectors: 0, mbr_type: 0 };
        let mut parts = [none; MAX_PARTS];
        parts[0] = Partition { start: 2048, sectors: 4096, mbr_type: 0x83 };
        parts[1] = Partition { start: 8192, sectors: 1024, mbr_type: 0x83 };
        assert!(partition::publish(&Table { scheme: Scheme::Mbr, parts, count: 2 }));
        DEVICE.lock().unwrap_or_else(|e| e.into_inner()).clear();
        OBSERVED.lock().unwrap_or_else(|e| e.into_inner()).clear();
        FAILS.store(false, Ordering::SeqCst);
        set_blk_probe(Some(probe));
        set_raw_layer(Some(8), false);
        azos_drv_block::write_observer::set(observer);
    }

    /// Run the worker's turn until nothing is left queued, and leave nothing behind.
    fn drain_layer() {
        while (KERNEL_IORING_OPS.block_service)() {}
    }

    fn done() {
        drain_layer();
        set_blk_probe(None);
        set_raw_layer(None, false);
        azos_drv_block::write_observer::clear();
        partition::reset_for_tests();
    }

    const OWNER: u32 = 0x7c20_0001;
    const EIO: i32 = Errno::EIO.to_syscall_ret() as i32;

    fn start(write: bool, sector: u64, buf: &[u8]) -> BlockStart {
        (KERNEL_IORING_OPS.block_start)(OWNER, 1, write, sector, buf.as_ptr(), buf.len())
    }

    fn token(s: BlockStart) -> u32 {
        match s {
            BlockStart::Queued(t) => t,
            other => panic!("not queued: {other:?}"),
        }
    }

    /// **A write is queued, not run; the device sees the SUBMIT's bytes when the
    /// worker waits for it.** The request layer is given the table's own
    /// buffer (a copy), so the caller's window can change meanwhile and the
    /// device still gets what was submitted. The partition start is added, the
    /// write observer hears of the run only after the device answered, and the
    /// entry is answered with the byte count.
    ///
    /// **Canaries.** Lend the layer the caller's pointer instead of the bounce:
    /// the device reads 0xEE. Notify the observer in `block_start`: `observed`
    /// is not empty before the service. Poll without the `Done` state: the
    /// first poll answers.
    #[test]
    fn a_queued_write_is_run_by_the_worker_from_a_copy_taken_at_the_submit() {
        if !azos_limits::IORING_ASYNC { return; }
        let _g = serial();
        scene();
        let mut window = vec![0xC3u8; 1024];
        let t = token(start(true, 7, &window));
        window.fill(0xEE);
        assert!(device().is_empty(), "the submit reached the device");
        assert_eq!(raw_queued().len(), 1);
        assert_eq!((raw_queued()[0].1, raw_queued()[0].2, raw_queued()[0].3), (true, 2048 + 7, 2));
        assert_eq!((KERNEL_IORING_OPS.block_poll)(t, window.as_mut_ptr(), 1024), None, "answered before the device ran");
        assert!(OBSERVED.lock().unwrap().is_empty());

        assert!(!(KERNEL_IORING_OPS.block_service)(), "nothing else was queued");
        let d = device();
        assert_eq!(d.len(), 1);
        assert_eq!((d[0].0, d[0].1, d[0].2), (true, 2055, 2));
        assert_eq!(d[0].3, vec![0xC3u8; 1024], "the device did not get the bytes of the submit");
        assert_eq!(*OBSERVED.lock().unwrap(), vec![(2055, 2)]);
        assert_eq!((KERNEL_IORING_OPS.block_poll)(t, window.as_mut_ptr(), 1024), Some(1024));
        assert_eq!(window, vec![0xEE; 1024], "a write answer touched the window");
        // Collected once: the token is not live any more.
        assert_eq!((KERNEL_IORING_OPS.block_poll)(t, window.as_mut_ptr(), 1024), Some(EIO));
        done();
    }

    /// A read lands the device's bytes in the caller's window at the poll, not
    /// before, and the table holds nothing afterwards.
    #[test]
    fn a_queued_read_reaches_its_window_only_when_polled() {
        if !azos_limits::IORING_ASYNC { return; }
        let _g = serial();
        scene();
        let mut window = vec![0x11u8; 1024];
        let t = token(start(false, 3, &window));
        drain_layer();
        assert_eq!(window, vec![0x11; 1024], "the device wrote the caller's window");
        assert_eq!((KERNEL_IORING_OPS.block_poll)(t, window.as_mut_ptr(), 1024), Some(1024));
        assert!(window[..512].iter().all(|&b| b == (2051u64 as u8)));
        assert!(window[512..].iter().all(|&b| b == (2052u64 as u8)));
        done();
    }

    /// A failed device request is `-EIO`, a write still tells the observer (the
    /// run may have landed in part), and the slot is free again.
    #[test]
    fn a_failed_request_answers_eio_and_a_write_still_notifies_the_cache() {
        if !azos_limits::IORING_ASYNC { return; }
        let _g = serial();
        scene();
        FAILS.store(true, Ordering::SeqCst);
        let buf = vec![0u8; 512];
        let t = token(start(true, 0, &buf));
        drain_layer();
        assert_eq!((KERNEL_IORING_OPS.block_poll)(t, buf.as_ptr() as *mut u8, 512), Some(EIO));
        assert_eq!(*OBSERVED.lock().unwrap(), vec![(2048, 1)]);
        done();
    }

    /// A run outside the partition is refused and recorded as the synchronous
    /// path refuses it, and never reaches the layer: a write one past the end,
    /// a read crossing it, a read past it. A run the layer cannot take
    /// (no queue on this board, a queue that takes nothing, more sectors than
    /// one command) is `Unqueueable`, and costs no slot.
    ///
    /// **Canary** (`block-scope-canary`, a gate row): `scope` drops the end
    /// check, and the first refusal reads `Queued`.
    #[test]
    fn a_run_outside_the_partition_is_refused_and_an_unqueueable_one_falls_back() {
        if !azos_limits::IORING_ASYNC { return; }
        let _g = serial();
        scene();
        let before = crate::block_host::BLOCK_SCOPE_REFUSALS.load(Ordering::SeqCst);
        let buf = vec![0u8; 512];
        let perm = BlockStart::Refused(azos_ipc::io_ring::IO_ERR_PERM);
        assert_eq!(start(true, 4096, &buf), perm, "a write one past the end");
        assert_eq!(start(false, 4095, &vec![0u8; 1024]), perm, "a read crossing the end");
        assert_eq!(start(false, u64::MAX, &buf), perm, "a read past the end");
        assert_eq!(crate::block_host::BLOCK_SCOPE_REFUSALS.load(Ordering::SeqCst), before + 3);
        assert!(raw_queued().is_empty());
        assert_eq!(start(true, 0, &vec![0u8; 100]), BlockStart::Refused(Errno::EINVAL.to_syscall_ret() as i32), "not whole sectors");

        let nine = vec![0u8; 9 * 512];
        assert_eq!(start(true, 0, &nine), BlockStart::Unqueueable, "longer than one command");
        set_raw_layer(Some(8), true);
        assert_eq!(start(true, 0, &buf), BlockStart::Unqueueable, "a queue that takes nothing");
        set_raw_layer(None, false);
        assert_eq!(start(true, 0, &buf), BlockStart::Unqueueable, "a disk not behind the request layer");
        set_raw_layer(Some(8), false);
        // None of those held a slot of the table.
        let mut tokens = Vec::new();
        for i in 0..128u64 {
            match start(false, i, &buf) {
                BlockStart::Queued(t) => tokens.push(t),
                other => panic!("request {i}: {other:?}"),
            }
        }
        drain_layer();
        for t in tokens {
            let mut b = vec![0u8; 512];
            assert!((KERNEL_IORING_OPS.block_poll)(t, b.as_mut_ptr(), 512).is_some());
        }
        done();
    }

    /// The table holds as many requests as the layer can: one more is
    /// `Unqueueable` (the entry then takes the synchronous path), and freeing
    /// one makes room.
    #[test]
    fn a_full_table_leaves_the_next_request_to_the_synchronous_path() {
        if !azos_limits::IORING_ASYNC { return; }
        let _g = serial();
        scene();
        let buf = vec![0u8; 512];
        let slots = azos_limits::MAX_IO_RINGS * azos_limits::IORING_MAX_PARKED;
        let slots = slots.min(azos_limits::NR_CPUS * azos_limits::BLK_QUEUE_DEPTH as usize);
        let mut tokens = Vec::new();
        for _ in 0..slots {
            tokens.push(token(start(false, 0, &buf)));
        }
        assert_eq!(start(false, 0, &buf), BlockStart::Unqueueable);
        drain_layer();
        let mut b = vec![0u8; 512];
        assert!((KERNEL_IORING_OPS.block_poll)(tokens[0], b.as_mut_ptr(), 512).is_some());
        tokens.push(token(start(false, 0, &buf)));
        drain_layer();
        for t in &tokens[1..] {
            assert!((KERNEL_IORING_OPS.block_poll)(*t, b.as_mut_ptr(), 512).is_some());
        }
        done();
    }

    /// An orphaned request still runs (a write was accepted), the worker
    /// collects it and frees its buffer, and nobody can ask for its answer.
    ///
    /// **Canary.** Do nothing in `block_orphan`: the answer stays in the table
    /// and `block_service` leaves the slot held (the layer's queue is empty but
    /// a later `block_poll` of the same token still answers).
    #[test]
    fn an_orphaned_request_is_run_and_freed_by_the_worker() {
        if !azos_limits::IORING_ASYNC { return; }
        let _g = serial();
        scene();
        let buf = vec![0x5Au8; 512];
        let t = token(start(true, 1, &buf));
        (KERNEL_IORING_OPS.block_orphan)(t);
        assert!(device().is_empty());
        drain_layer();
        assert_eq!(device().len(), 1, "an accepted write was dropped with its ring");
        assert_eq!((KERNEL_IORING_OPS.block_poll)(t, buf.as_ptr() as *mut u8, 512), Some(EIO), "the slot was left held");
        // The worker's turn with nothing in flight is a no-op.
        assert!(!(KERNEL_IORING_OPS.block_service)());
        done();
    }

    /// Sectors (absolute) the write-back cache holds unwritten, if any.
    static DIRTY: Mutex<Option<(u64, u32)>> = Mutex::new(None);
    /// Ranges the read observer was called for.
    static READS: Mutex<Vec<(u64, u32)>> = Mutex::new(Vec::new());

    fn dirty_probe(sector: u64, count: u32) -> bool {
        match *DIRTY.lock().unwrap_or_else(|e| e.into_inner()) {
            Some((d, n)) => sector < d + n as u64 && d < sector + count as u64,
            None => false,
        }
    }

    /// FAT32's `fat32_before_medium_read`: writes the range back, which empties
    /// the dirty set.
    fn read_observer(sector: u64, count: u32) {
        READS.lock().unwrap_or_else(|e| e.into_inner()).push((sector, count));
        if dirty_probe(sector, count) {
            *DIRTY.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
    }

    fn dirty_scene(range: Option<(u64, u32)>) {
        READS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        *DIRTY.lock().unwrap_or_else(|e| e.into_inner()) = range;
        azos_drv_block::write_observer::set_read(read_observer, dirty_probe);
    }

    /// **A read of a range the write-back cache holds dirty is not started by
    /// the submit.** `block_start` answers `Dirty` with no request queued, no
    /// device command and no call of the read observer (which would write the
    /// sectors out and wait for the device); a range the cache does not hold
    /// is queued, and the observer is not called for it either.
    ///
    /// **Canaries.** Call `note_external_read` in `block_start` (the old
    /// code): `READS` is not empty after the dirty start. Drop the
    /// `read_would_wait` test: the dirty start answers `Queued`.
    #[test]
    fn a_read_of_a_dirty_cached_range_is_not_started_by_the_submit() {
        if !azos_limits::IORING_ASYNC { return; }
        let _g = serial();
        scene();
        // Partition 0 starts at 2048: sector 3 is absolute 2051.
        dirty_scene(Some((2051, 1)));
        let buf = vec![0u8; 1024];
        assert_eq!(start(false, 2, &buf), BlockStart::Dirty, "sectors 2050..2052 hold 2051");
        assert!(raw_queued().is_empty(), "a dirty read took a request slot");
        assert!(READS.lock().unwrap().is_empty(), "the submit called the write-back observer");
        assert!(device().is_empty());
        // A write over the same range is queued as usual.
        let t = token(start(true, 3, &buf[..512]));
        // A read elsewhere, and the range with the cache empty: queued.
        let t2 = token(start(false, 100, &buf));
        assert!(READS.lock().unwrap().is_empty(), "the submit called the write-back observer for a clean range");
        drain_layer();
        let mut w = vec![0u8; 1024];
        assert!((KERNEL_IORING_OPS.block_poll)(t, w.as_mut_ptr(), 512).is_some());
        assert!((KERNEL_IORING_OPS.block_poll)(t2, w.as_mut_ptr(), 1024).is_some());
        *DIRTY.lock().unwrap() = None;
        let t3 = token(start(false, 2, &buf));
        drain_layer();
        assert!((KERNEL_IORING_OPS.block_poll)(t3, w.as_mut_ptr(), 1024).is_some());
        assert!(READS.lock().unwrap().is_empty());
        done();
    }

    /// **Through the ring.** A submit of a read over dirty cached sectors
    /// completes nothing, calls no observer and reaches no device; the worker's
    /// pass writes the cache back (the observer) before it reads, and posts the
    /// bytes. A read after it, over the same sectors, is queued again.
    ///
    /// **Canary.** Treat `Dirty` as `Unqueueable` in `dispatch_block`: the
    /// submit returns 1 and `READS` holds the range before the worker runs.
    #[test]
    fn a_dirty_cached_read_entry_is_written_back_and_run_by_the_worker() {
        if !azos_limits::IORING_ASYNC { return; }
        let _g = serial();
        scene();
        dirty_scene(Some((2057, 1)));
        let (s, pt) = ring3();
        let (cap, _va, ring) = create(pt);
        grant_dev(s.tid, azos_devif::key::BLOCK, 1, CapPerms::RW);
        let entry = |op, off, len, sector: u16, ud| SqEntry { opcode: op, flags: 0, param0: 1, param1: off, param2: len, addr: sector, reg: 0, user_data: ud };
        unsafe {
            let tail = (*ring).sq_tail.load(Ordering::Acquire);
            (*ring).sq_entries[tail as usize % RING_SQ_SIZE] = entry(OP_BLOCK_READ, 0, 1024, 8, 1);
            (*ring).sq_tail.store(tail.wrapping_add(1), Ordering::Release);
            let cq = (*ring).cq_tail.load(Ordering::Acquire);
            assert_eq!(sys_ioring_submit_typed(cap), 0, "the submit completed a dirty read");
            assert!(READS.lock().unwrap().is_empty(), "the submit wrote the cache back");
            assert!(device().is_empty(), "the submit reached the device");
            assert!(raw_queued().is_empty());
            assert_eq!((*ring).cq_tail.load(Ordering::Acquire), cq);

            azos_ipc::io_ring::io_ring_worker_pass();
            assert_eq!(*READS.lock().unwrap(), vec![(2056, 2)], "the worker did not write the cache back");
            assert_eq!((*ring).cq_tail.load(Ordering::Acquire), cq.wrapping_add(1));
            let c = (*ring).cq_entries[cq as usize % RING_CQ_SIZE];
            assert_eq!((c.user_data, c.result, c.flags), (1, 1024, 0));
            assert_eq!(device().iter().map(|d| (d.0, d.1, d.2)).collect::<Vec<_>>(), vec![(false, 2056, 2)]);
            (*ring).cq_head.store((*ring).cq_tail.load(Ordering::Acquire), Ordering::Release);

            // The cache is clean now: the same read is queued by the submit.
            let tail = (*ring).sq_tail.load(Ordering::Acquire);
            (*ring).sq_entries[tail as usize % RING_SQ_SIZE] = entry(OP_BLOCK_READ, 0, 1024, 8, 2);
            (*ring).sq_tail.store(tail.wrapping_add(1), Ordering::Release);
            assert_eq!(sys_ioring_submit_typed(cap), 0);
            assert_eq!(raw_queued().len(), 1);
            azos_ipc::io_ring::io_ring_worker_pass();
        }
        assert_eq!(READS.lock().unwrap().len(), 1, "a clean read called the observer");
        assert_eq!(sys_ioring_destroy_typed(cap), 0);
        done();
    }

    /// **Through the ring, on the kernel table.** An owner holding the
    /// partition's endpoint submits a write and a read: the submit completes
    /// nothing, the worker's pass does, the write `CQE_F_QUEUED` and the read
    /// unflagged with the device's bytes in the entry's window; the ring
    /// destroyed with a request in flight leaves the table empty after the
    /// worker's turn.
    #[test]
    fn block_entries_complete_through_the_cq_on_the_kernel_table() {
        if !azos_limits::IORING_ASYNC { return; }
        let _g = serial();
        scene();
        let (s, pt) = ring3();
        let (cap, _va, ring) = create(pt);
        grant_dev(s.tid, azos_devif::key::BLOCK, 1, CapPerms::RW);
        let entry = |op, off, len, sector: u16, ud| SqEntry { opcode: op, flags: 0, param0: 1, param1: off, param2: len, addr: sector, reg: 0, user_data: ud };
        unsafe {
            (&mut (*ring).data_buf)[..512].fill(0x77);
            let tail = (*ring).sq_tail.load(Ordering::Acquire);
            (*ring).sq_entries[tail as usize % RING_SQ_SIZE] = entry(OP_BLOCK_WRITE, 0, 512, 9, 1);
            (*ring).sq_entries[(tail as usize + 1) % RING_SQ_SIZE] = entry(OP_BLOCK_READ, 512, 1024, 20, 2);
            (*ring).sq_tail.store(tail.wrapping_add(2), Ordering::Release);
            let cq = (*ring).cq_tail.load(Ordering::Acquire);
            assert_eq!(sys_ioring_submit_typed(cap), 0, "the submit completed a block entry");
            assert!(device().is_empty(), "the submit reached the device");
            assert_eq!(raw_queued().len(), 2);
            assert_eq!((*ring).cq_tail.load(Ordering::Acquire), cq);

            azos_ipc::io_ring::io_ring_worker_pass();
            assert_eq!((*ring).cq_tail.load(Ordering::Acquire), cq.wrapping_add(2));
            let a = (*ring).cq_entries[cq as usize % RING_CQ_SIZE];
            let b = (*ring).cq_entries[(cq as usize + 1) % RING_CQ_SIZE];
            let mut got = [(a.user_data, a.result, a.flags), (b.user_data, b.result, b.flags)];
            got.sort();
            assert_eq!(got, [(1, 512, CQE_F_QUEUED), (2, 1024, 0)]);
            assert!((&(*ring).data_buf)[512..1024].iter().all(|&x| x == (2068u64 as u8)));
            assert!((&(*ring).data_buf)[1024..1536].iter().all(|&x| x == (2069u64 as u8)));
            assert_eq!(device().iter().map(|d| (d.0, d.1, d.2)).collect::<Vec<_>>(), vec![(true, 2057, 1), (false, 2068, 2)]);
            (*ring).cq_head.store((*ring).cq_tail.load(Ordering::Acquire), Ordering::Release);

            // A request in flight when the ring goes.
            let tail = (*ring).sq_tail.load(Ordering::Acquire);
            (*ring).sq_entries[tail as usize % RING_SQ_SIZE] = entry(OP_BLOCK_WRITE, 0, 512, 9, 3);
            (*ring).sq_tail.store(tail.wrapping_add(1), Ordering::Release);
            assert_eq!(sys_ioring_submit_typed(cap), 0);
        }
        assert_eq!(raw_queued().len(), 1);
        assert_eq!(sys_ioring_destroy_typed(cap), 0);
        drain_layer();
        assert!(raw_queued().is_empty(), "the ring's request was left in the layer");
        assert_eq!(device().len(), 3, "an accepted write was lost with its ring");
        done();
    }
}

/// **Who runs a file entry.** With Kconfig `IORING_ASYNC` a task that may block
/// still hands its file entries to the worker (`file_inline` answers `false`);
/// the runtime canary `ioring-rt-inline` puts the inline run back for every
/// task. Without the option the answer is `true`.
///
/// **Canary.** Answer `true` unconditionally in `file_inline`: the first line
/// goes red.
#[test]
fn a_file_entry_runs_inline_only_without_ioring_async_or_under_the_canary() {
    use std::sync::atomic::Ordering::SeqCst;
    let _g = serial();
    crate::ioring_ops::RT_INLINE_CANARY.store(false, SeqCst);
    assert_eq!((KERNEL_IORING_OPS.file_inline)(), !azos_limits::IORING_ASYNC);
    crate::ioring_ops::RT_INLINE_CANARY.store(true, SeqCst);
    assert!((KERNEL_IORING_OPS.file_inline)(), "the canary did not put the inline run back");
    assert!((KERNEL_IORING_OPS.may_block)(), "the canary lets an RT task block");
    crate::ioring_ops::RT_INLINE_CANARY.store(false, SeqCst);
}

// ── The IDL entry (`OP_CALL`) ─────────────────────────────────────────────
//
// One entry carries an IDL request on a kernel-hosted endpoint handle, and the
// kernel answers it with the call's own resolve, mask, profile and dispatch
// (`ioring_ops::idl_call`). The oracle is the call itself: `khost::serve` on
// the same request.

/// Grant `tid` an endpoint to the kernel-hosted interface `key` for `badge`,
/// with `perms` and the op mask `ops` (0: none), and answer its handle.
fn grant_ep(tid: u32, key: u16, badge: u32, perms: CapPerms, ops: u64) -> u32 {
    azos_ipc::endpoint::kernel_endpoint_cap_ops(tid, perms, key, badge, ops)
        .expect("cap table full")
        .raw()
        .as_raw()
}

/// The message window of the entry at `off`.
unsafe fn put_window(ring: *mut IoRing, off: usize, words: &[u64]) {
    for (i, w) in words.iter().enumerate() {
        (&mut (*ring).data_buf)[off + i * 8..off + i * 8 + 8].copy_from_slice(&w.to_ne_bytes());
    }
}

unsafe fn window(ring: *const IoRing, off: usize) -> [u64; azos_ipc::io_ring::CALL_WORDS] {
    let mut out = [0u64; azos_ipc::io_ring::CALL_WORDS];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u64::from_ne_bytes((&(*ring).data_buf)[off + i * 8..off + i * 8 + 8].try_into().unwrap());
    }
    out
}

/// Queue the request `words` on endpoint `ep` in the window at `off`.
unsafe fn queue_call(ring: *mut IoRing, ep: u32, off: u32, words: &[u64], tag: u64) {
    put_window(ring, off as usize, words);
    let tail = (*ring).sq_tail.load(Ordering::Acquire);
    (*ring).sq_entries[tail as usize % RING_SQ_SIZE] =
        SqEntry { user_data: tag, ..sqe(azos_ipc::io_ring::OP_CALL, ep, off, words.len() as u32) };
    (*ring).sq_tail.store(tail.wrapping_add(1), Ordering::Release);
}

/// Submit what is queued and take every completion.
unsafe fn submit_queued(cap: u64, ring: *mut IoRing) -> Vec<CqEntry> {
    let cq = (*ring).cq_tail.load(Ordering::Acquire);
    assert!(sys_ioring_submit_typed(cap) >= 0);
    let end = (*ring).cq_tail.load(Ordering::Acquire);
    let out = (cq..end).map(|i| (*ring).cq_entries[i as usize % RING_CQ_SIZE]).collect();
    (*ring).cq_head.store(end, Ordering::Release);
    out
}

fn sensor_read_hdr() -> u64 {
    use azos_devif::SensorIdl as S;
    azos_idl::header(S::ID, S::LEVEL, S::OP_READ)
}

fn motor_speed_hdr() -> u64 {
    use azos_devif::MotorIdl as M;
    azos_idl::header(M::ID, M::LEVEL, M::OP_SPEED)
}

/// The descriptor-form call on the same state: `khost::serve` for `tid`
/// through `ep`, the oracle of an `OP_CALL`.
fn served_reply(tid: u32, ep: u32, key: u16, words: &[u64]) -> [u64; azos_ipc::io_ring::CALL_WORDS] {
    let who = crate::khost::admit(tid, ep, words[0]).expect("the capability resolves");
    let mut req = azos_abi::ipc_msg::MsgDesc { version: azos_abi::ipc_msg::MSG_VERSION, n_words: words.len() as u8, ..Default::default() };
    req.words[..words.len()].copy_from_slice(words);
    let mut rep = azos_abi::ipc_msg::MsgDesc::default();
    crate::khost::serve(key, &who, &req, &mut rep);
    let mut out = [0u64; azos_ipc::io_ring::CALL_WORDS];
    out[..rep.n_words as usize].copy_from_slice(&rep.words[..rep.n_words as usize]);
    out
}

/// **An IDL entry without the authority the call needs does nothing.** A handle
/// the owner does not hold is refused with `-ECAPPERMS` and the refusal flag;
/// an endpoint whose op mask omits `read` is refused the same way; an endpoint
/// with `WRITE` alone is served and answers `DENIED`, the op's class check. In
/// none of them are the encoders read. With `READ` the reply is the `Sensor`
/// interface's sample of the encoders.
///
/// **Canary** (the capability check skipped): build the caller in `idl_call`
/// from the handle's badge with every right in place of `khost::admit`'s: the
/// masked and the WRITE-only entries read the encoders.
#[test]
fn an_idl_entry_without_the_capability_is_refused_and_reads_nothing() {
    let _g = serial();
    let (s, pt) = ring3();
    azos_robot::shim_set_encoder(21, -4);
    let (cap, _va, ring) = create(pt);
    let enc = SENSOR_TYPE_ENCODER as u32;
    let reads = azos_robot::shim_encoder_reads();

    unsafe { queue_call(ring, 0x77, 0, &[sensor_read_hdr()], 1) };
    let c = unsafe { submit_queued(cap, ring) };
    assert_eq!(done(c[0]), (Errno::ECAPPERMS.to_syscall_ret() as i32, CQE_F_REFUSED), "an unheld handle");

    let masked = grant_ep(s.tid, azos_devif::key::SENSOR, enc, CapPerms::READ, 1 << azos_devif::SensorIdl::OP_BIND_VDSO);
    unsafe { queue_call(ring, masked, 64, &[sensor_read_hdr()], 2) };
    let c = unsafe { submit_queued(cap, ring) };
    assert_eq!(done(c[0]), (Errno::ECAPPERMS.to_syscall_ret() as i32, CQE_F_REFUSED), "a mask without `read`");
    assert_eq!(unsafe { window(ring, 64) }[0], sensor_read_hdr(), "a refused entry wrote its window");

    let write_only = grant_ep(s.tid, azos_devif::key::SENSOR, enc, CapPerms::WRITE, 0);
    unsafe { queue_call(ring, write_only, 128, &[sensor_read_hdr()], 3) };
    let c = unsafe { submit_queued(cap, ring) };
    assert_eq!(done(c[0]), (0, 0), "the op's class is the interface's answer, not a ring refusal");
    assert_eq!(unsafe { window(ring, 128) }[1], azos_devif::outcome::DENIED as u64);
    assert_eq!(azos_robot::shim_encoder_reads(), reads, "an entry without READ read the encoders");

    let held = grant_ep(s.tid, azos_devif::key::SENSOR, enc, CapPerms::READ, 0);
    unsafe { queue_call(ring, held, 192, &[sensor_read_hdr()], 4) };
    let c = unsafe { submit_queued(cap, ring) };
    assert_eq!(done(c[0]), (0, 0));
    let rep = unsafe { window(ring, 192) };
    assert_eq!(rep[1], azos_devif::outcome::OK as u64);
    assert_eq!(rep[2], 16, "the encoder pair is 16 bytes");
    assert_eq!((rep[5] as i64, rep[6] as i64), (21, -4));
}

/// **The profile is asked as for the call**: `SYS_IPC_CALL` first, then the
/// interface once the handle names it. A row without the `sensor` interface
/// refuses the held entry with `-EPERM` and reads nothing; audit mode runs it;
/// listed, it runs. A row without `SYS_IPC_CALL` refuses it too.
///
/// **Canary.** Drop the `iface_allowed` test from `idl_call`: the unlisted
/// entry reads the encoders.
#[test]
fn a_profile_without_the_sensor_interface_refuses_the_idl_entry() {
    let _g = serial();
    let (s, pt) = ring3();
    azos_robot::shim_set_encoder(5, 6);
    let ep = grant_ep(s.tid, azos_devif::key::SENSOR, SENSOR_TYPE_ENCODER as u32, CapPerms::READ, 0);
    let (cap, _va, ring) = create(pt);
    let run = |f: SyscallFilter| {
        azos_sched::scheduler::set_current_syscall_filter(f);
        unsafe {
            queue_call(ring, ep, 0, &[sensor_read_hdr()], 9);
            done(submit_queued(cap, ring)[0])
        }
    };
    let eperm = (Errno::EPERM.to_syscall_ret() as i32, CQE_F_REFUSED);
    let reads = azos_robot::shim_encoder_reads();
    assert_eq!(run(profile(&[nr::SYS_RING_ENTER], false)), eperm, "no SYS_IPC_CALL");
    assert_eq!(run(profile(&[nr::SYS_RING_ENTER, nr::SYS_IPC_CALL], false)), eperm, "no `sensor` interface");
    assert_eq!(azos_robot::shim_encoder_reads(), reads, "a denied entry read the encoders");
    assert_eq!(run(profile(&[nr::SYS_RING_ENTER, nr::SYS_IPC_CALL], true)), (0, 0), "audit mode");
    let mut listed = profile(&[nr::SYS_RING_ENTER, nr::SYS_IPC_CALL], false);
    listed.allow_iface(azos_devif::key::SENSOR);
    assert_eq!(run(listed), (0, 0), "a listed interface");
}

/// **The sensor read through the IDL entry is the call's**: the same reply
/// words as `khost::serve` on the same request, and the encoders' bytes as the
/// interface's record.
///
/// **Canary.** Copy the reply's words from index 1 in `idl_call`: the status
/// word differs from the call's.
#[test]
fn the_idl_sensor_read_answers_what_the_call_answers() {
    let _g = serial();
    let (s, pt) = ring3();
    azos_robot::shim_set_encoder(1234, 5678);
    let enc = SENSOR_TYPE_ENCODER as u32;
    let ep = grant_ep(s.tid, azos_devif::key::SENSOR, enc, CapPerms::READ, 0);
    let (cap, _va, ring) = create(pt);
    unsafe { queue_call(ring, ep, 256, &[sensor_read_hdr()], 1) };
    let c = unsafe { submit_queued(cap, ring) };
    assert_eq!(done(c[0]), (0, 0));
    let rep = unsafe { window(ring, 256) };
    let mut oracle = served_reply(s.tid, ep, azos_devif::key::SENSOR, &[sensor_read_hdr()]);
    // The acquisition stamp is the read's own.
    oracle[4] = rep[4];
    assert_eq!(rep, oracle, "the IDL entry and the call disagree");
    assert_eq!((rep[5] as i64, rep[6] as i64), (1234, 5678));
}

/// **Both wheels through two IDL entries in one submit are the call's
/// command, and the latch holds them the same way.** Driven: each wheel's
/// `speed` writes its duty. Latched:
/// both write duty 0 and the entries answer `REFUSED` (served: the halt rule
/// is the interface's answer). Each reply equals the register-form call's on
/// the same state.
///
/// **Canary.** Make `MotorServer::speed` answer `OK` whatever the motor
/// layer said: the latched replies read `OK`.
#[test]
fn two_idl_motor_entries_command_what_the_call_commands() {
    let _g = serial();
    let (s, pt) = ring3();
    let l = grant_ep(s.tid, azos_devif::key::MOTOR, 0, CapPerms::RW, 0);
    let r = grant_ep(s.tid, azos_devif::key::MOTOR, 1, CapPerms::RW, 0);
    wheels();
    let (cap, _va, ring) = create(pt);

    unsafe {
        queue_call(ring, l, 0, &[motor_speed_hdr(), 30], 1);
        queue_call(ring, r, 64, &[motor_speed_hdr(), 40], 2);
    }
    let c = unsafe { submit_queued(cap, ring) };
    assert_eq!(c.iter().map(|c| (c.user_data, c.result, c.flags)).collect::<Vec<_>>(), vec![(1, 0, 0), (2, 0, 0)]);
    let ok = vec![0, azos_devif::outcome::OK as u64];
    assert_eq!(unsafe { (window(ring, 0)[..2].to_vec(), window(ring, 64)[..2].to_vec()) }, (ok.clone(), ok));
    assert_eq!(pwm_calls(), vec![(PwmOp::SetDutyPct, CH[0], 30), (PwmOp::SetDutyPct, CH[1], 40)]);
    for id in 0..2 {
        assert_eq!(crate::motor_commander::commander(id), commander_of(s.tid), "wheel {id} names no commander");
    }

    ESTOP.store(true, Ordering::SeqCst);
    clear_pwm_calls();
    unsafe {
        queue_call(ring, l, 0, &[motor_speed_hdr(), 60], 1);
        queue_call(ring, r, 64, &[motor_speed_hdr(), 60], 2);
    }
    let c = unsafe { submit_queued(cap, ring) };
    assert_eq!(c.iter().map(|c| (c.result, c.flags)).collect::<Vec<_>>(), vec![(0, 0), (0, 0)]);
    let refused = vec![0, azos_devif::outcome::REFUSED as u64];
    assert_eq!(unsafe { (window(ring, 0)[..2].to_vec(), window(ring, 64)[..2].to_vec()) }, (refused.clone(), refused));
    assert_eq!(pwm_calls(), vec![(PwmOp::SetDutyPct, CH[0], 0), (PwmOp::SetDutyPct, CH[1], 0)]);
    for id in 0..2 {
        assert!(matches!(azos_robot::motor_state(id), Some((_, 0))), "wheel {id} recorded a speed under the latch");
    }
    assert_eq!(unsafe { window(ring, 0) }, served_reply(s.tid, l, azos_devif::key::MOTOR, &[motor_speed_hdr(), 60]));
}

/// **A task-hosted endpoint is not served from a pass**: `-ENOSYS`, refused,
/// and the window untouched.
///
/// **Canary.** Answer a task-hosted endpoint with `Ok(())` in `idl_call`: the
/// completion is not refused.
#[test]
fn an_idl_entry_on_a_task_hosted_endpoint_is_refused() {
    let _g = serial();
    let (s, pt) = ring3();
    let ep = azos_ipc::endpoint::endpoint_create_cap(s.tid, CapPerms::RW).expect("an endpoint").raw().as_raw();
    let (cap, _va, ring) = create(pt);
    unsafe { queue_call(ring, ep, 0, &[motor_speed_hdr(), 1], 1) };
    let c = unsafe { submit_queued(cap, ring) };
    assert_eq!(done(c[0]), (Errno::ENOSYS.to_syscall_ret() as i32, CQE_F_REFUSED));
    assert_eq!(unsafe { window(ring, 0) }[..2], [motor_speed_hdr(), 1]);
}

/// **An actuator argument out of range is refused, not clamped**: a wheel
/// speed past 100 (a reverse written as `u32` among them), a PWM duty past 100
/// percent or past the period, a GPIO level other than 0 or 1 and a PID target
/// past 100 percent answer `BAD_ARGUMENT` through an `OP_CALL`, and nothing is
/// written. The motor layer and the PWM driver clamp, so a clamp here would be
/// full speed forward.
///
/// **Canary.** Delete the `pct > 100` test from `MotorServer::speed`: the
/// first entry drives wheel 0 at 100.
#[test]
fn an_actuator_argument_out_of_range_is_refused_not_clamped() {
    let _g = serial();
    let (s, pt) = ring3();
    let l = grant_ep(s.tid, azos_devif::key::MOTOR, 0, CapPerms::RW, 0);
    let _r = grant_ep(s.tid, azos_devif::key::MOTOR, 1, CapPerms::RW, 0);
    let pwm = grant_ep(s.tid, azos_devif::key::PWM, FREE_CH, CapPerms::RW, 0);
    let pin = grant_ep(s.tid, azos_devif::key::GPIO, azos_devif::gpio::badge(0, 9), CapPerms::RW, 0);
    wheels();
    let (cap, _va, ring) = create(pt);
    let call = |ep: u32, words: &[u64]| unsafe {
        queue_call(ring, ep, 0, words, 1);
        let c = submit_queued(cap, ring);
        assert_eq!(done(c[0]), (0, 0), "the ring refused a held entry");
        window(ring, 0)[1] as u32
    };
    let bad = azos_devif::outcome::BAD_ARGUMENT;
    let motor = |op| {
        use azos_devif::MotorIdl as M;
        azos_idl::header(M::ID, M::LEVEL, op)
    };
    let pwm_op = |op| {
        use azos_devif::PwmIdl as P;
        azos_idl::header(P::ID, P::LEVEL, op)
    };
    use azos_devif::{MotorIdl, PwmIdl};
    assert_eq!(call(l, &[motor_speed_hdr(), 101]), bad, "speed 101");
    assert_eq!(call(l, &[motor_speed_hdr(), u32::MAX as u64]), bad, "speed -1 as u32");
    assert_eq!(call(l, &[motor_speed_hdr(), (-40i32) as u32 as u64]), bad, "speed -40 as u32");
    assert_eq!(call(l, &[motor(MotorIdl::OP_PID_TARGET), 101, 0]), bad, "PID target 101");
    assert_eq!(call(l, &[motor(MotorIdl::OP_PID_TARGET), 0, (-101i64) as u64]), bad, "PID target -101");
    assert_eq!(call(pwm, &[pwm_op(PwmIdl::OP_SET_DUTY_PCT), 101]), bad, "duty 101 %");
    assert_eq!(call(pwm, &[pwm_op(PwmIdl::OP_SET_DUTY), u32::MAX as u64]), bad, "duty past the period");
    assert_eq!(call(pwm, &[pwm_op(PwmIdl::OP_SET_DUTY), 600_000]), azos_devif::outcome::OK);
    assert_eq!(call(pwm, &[pwm_op(PwmIdl::OP_SET_PERIOD), 200_000]), bad, "a period shorter than the duty");
    assert_eq!(call(pwm, &[pwm_op(PwmIdl::OP_SET_DUTY), 0]), azos_devif::outcome::OK);
    clear_pwm_calls();
    BOARD_OPS.lock().unwrap().clear();
    set_gpio_probe(Some(board_probe));
    assert_eq!(call(pin, &[gpio_hdr(azos_devif::GpioIdl::OP_WRITE), 2]), bad, "GPIO level 2");
    assert_eq!(*BOARD_OPS.lock().unwrap(), vec![], "a refused GPIO level reached the driver");
    assert!(pwm_calls().is_empty(), "an out-of-range entry wrote {:?}", pwm_calls());
    assert!(matches!(azos_robot::motor_state(0), Some((_, 0))), "wheel 0 recorded a speed");

    // In range, the same ops run.
    assert_eq!(call(l, &[motor_speed_hdr(), 100]), azos_devif::outcome::OK);
    assert_eq!(pwm_calls(), vec![(PwmOp::SetDutyPct, CH[0], 100)]);
}

/// **An interface whose ops may wait is not served from a pass**: `Clock`
/// and `Power` (whose `sync` does block I/O) answer `-ENOSYS` with the
/// refusal flag, the window untouched, from a real-time submitter too, as a
/// task-hosted endpoint does. The device interfaces are (`khost::ring_served`).
///
/// **Canary.** Answer `true` from `khost::ring_served`: the clock entry is
/// served.
#[test]
fn an_interface_that_may_wait_is_not_served_from_a_pass() {
    let _g = serial();
    let (s, pt) = ring3();
    let clock = grant_ep(s.tid, azos_devif::key::CLOCK, 0, CapPerms::RW, 0);
    let power = grant_ep(s.tid, azos_devif::key::POWER, 0, CapPerms::RW, 0);
    let (cap, _va, ring) = create(pt);
    let enosys = (Errno::ENOSYS.to_syscall_ret() as i32, CQE_F_REFUSED);
    let status = {
        use azos_devif::ClockIdl as C;
        azos_idl::header(C::ID, C::LEVEL, C::OP_STATUS)
    };
    unsafe { queue_call(ring, clock, 0, &[status], 1) };
    assert_eq!(done(unsafe { submit_queued(cap, ring) }[0]), enosys, "a clock entry was served from a pass");
    let sync = {
        use azos_devif::PowerIdl as P;
        azos_idl::header(P::ID, P::LEVEL, P::OP_SYNC)
    };
    let prio = azos_sched::scheduler::current_task_base_priority();
    azos_sched::scheduler::shim_set_base_priority(azos_sched::RT_PRIORITY_THRESHOLD - 1);
    unsafe { queue_call(ring, power, 64, &[sync], 2) };
    let c = unsafe { submit_queued(cap, ring) };
    azos_sched::scheduler::shim_set_base_priority(prio);
    assert_eq!(done(c[0]), enosys, "an RT submitter's sync was served from a pass");
    assert_eq!(unsafe { window(ring, 64) }[0], sync, "a refused entry wrote its window");
    use azos_devif::key;
    for k in [key::ADC, key::ENTROPY, key::CLOCK, key::POWER, key::NET, key::VOLUME] {
        assert!(!crate::khost::ring_served(k, 0), "host key {k} is served from a pass");
    }
    // The device rows follow their drivers' declarations (the stand-ins': a
    // bus that does not sleep, a converter that waits, register writes).
    assert!(crate::khost::ring_served(key::SENSOR, SENSOR_TYPE_ENCODER as u32));
    assert!(!crate::khost::ring_served(key::SENSOR, SENSOR_TYPE_BATTERY as u32), "the ADS1115 waits in its queue");
    assert!(crate::khost::ring_served(key::MOTOR, 0) && crate::khost::ring_served(key::PWM, FREE_CH));
    assert_eq!(crate::khost::ring_served(key::I2C, 0), !azos_drv_bus::i2c::transfer_may_sleep());
}

/// **A device whose bus may sleep is not served from a pass, and its typed
/// call still is.** With the I2C bus modelled as one that sleeps (a DesignWare
/// or K1 controller waiting for a transaction), an `I2c` entry and the IMU's
/// `Sensor::read` (an I2C part) answer `-ENOSYS`, while the encoders (a value
/// a task left) are served; a GPIO expander that declares `may_sleep` is
/// refused the same way, and the board's pins are served. The call on the
/// same endpoints is answered.
///
/// **Canary.** Answer `true` from `devices::i2c_ring_served`: the I2C entry is
/// served on the sleeping bus.
#[test]
fn a_device_whose_bus_may_sleep_is_not_served_from_a_pass() {
    struct Bus;
    impl Drop for Bus {
        fn drop(&mut self) {
            azos_drv_bus::i2c::shim_set_transfer_may_sleep(false);
            RING_EXPANDER_SLEEPS.store(false, Ordering::SeqCst);
            let _ = azos_drv_gpio::chips::unregister(super::harness::GPIO_EXPANDER_DEV, &mut || false);
            set_gpio_probe(None);
        }
    }
    let _g = serial();
    let (s, pt) = ring3();
    let _bus = Bus;
    azos_drv_bus::i2c::shim_set_transfer_may_sleep(true);
    RING_EXPANDER_SLEEPS.store(true, Ordering::SeqCst);
    EXPANDER_WRITES.lock().unwrap().clear();
    set_gpio_probe(Some(board_probe));
    assert_eq!(azos_drv_gpio::chips::register(super::harness::GPIO_EXPANDER_DEV, &RING_EXPANDER), Ok(1));
    let i2c = grant_ep(s.tid, azos_devif::key::I2C, azos_devif::i2c::badge(1, 0x68), CapPerms::RW, 0);
    let imu = grant_ep(s.tid, azos_devif::key::SENSOR, SENSOR_TYPE_IMU as u32, CapPerms::READ, 0);
    let enc = grant_ep(s.tid, azos_devif::key::SENSOR, SENSOR_TYPE_ENCODER as u32, CapPerms::READ, 0);
    let x = grant_ep(s.tid, azos_devif::key::GPIO, azos_devif::gpio::badge(1, 3), CapPerms::RW, 0);
    let board = grant_ep(s.tid, azos_devif::key::GPIO, azos_devif::gpio::badge(0, 9), CapPerms::RW, 0);
    let (cap, _va, ring) = create(pt);
    let detect = {
        use azos_devif::I2cIdl as I;
        azos_idl::header(I::ID, I::LEVEL, I::OP_DETECT)
    };
    let gpio_write = gpio_hdr(azos_devif::GpioIdl::OP_WRITE);
    let run = |ep: u32, words: &[u64]| unsafe {
        queue_call(ring, ep, 0, words, 1);
        done(submit_queued(cap, ring)[0])
    };
    let enosys = (Errno::ENOSYS.to_syscall_ret() as i32, CQE_F_REFUSED);
    assert_eq!(run(i2c, &[detect]), enosys, "an I2C entry was served on a bus that sleeps");
    assert_eq!(run(imu, &[sensor_read_hdr()]), enosys, "the IMU was read in a pass on a bus that sleeps");
    assert_eq!(run(x, &[gpio_write, 1]), enosys, "a sleeping expander's pin was driven in a pass");
    assert_eq!(run(enc, &[sensor_read_hdr()]), (0, 0), "the encoders are not on the bus");
    assert_eq!(run(board, &[gpio_write, 1]), (0, 0), "the board's pins do not sleep");
    assert_eq!(*EXPANDER_WRITES.lock().unwrap(), vec![], "the refused expander entry reached its driver");
    // The typed call is the client's door to the same devices.
    assert_eq!(served_reply(s.tid, x, azos_devif::key::GPIO, &[gpio_write, 1])[0], 0);
}

/// **The poller asks the OWNER's profile for the interface**, as for the
/// call: a row of the owner without the `sensor` interface refuses the owner's
/// held sensor entry run by the poller (a kernel task, unfiltered); listed, it
/// runs.
///
/// **Canary.** Answer `current_iface_verdict(key)` in both arms of
/// `iface_allowed`: the unlisted entry runs.
#[test]
fn a_poller_pass_asks_the_owners_profile_for_the_interface() {
    let _g = serial();
    let (_s, _p, _f, owner, ring, r) = polled_ring();
    let ep = grant_ep(owner, azos_devif::key::SENSOR, SENSOR_TYPE_ENCODER as u32, CapPerms::READ, 0);
    let row = profile(&[nr::SYS_RING_ENTER, nr::SYS_IPC_CALL], false);
    azos_sched::scheduler::shim_set_task_filter(owner, Some(row.clone()));
    let c = unsafe { poll_call(ring, r, ep, &[sensor_read_hdr()]) };
    assert_eq!(done(c), (Errno::EPERM.to_syscall_ret() as i32, CQE_F_REFUSED), "ran past the owner's row");
    let mut listed = row;
    listed.allow_iface(azos_devif::key::SENSOR);
    azos_sched::scheduler::shim_set_task_filter(owner, Some(listed));
    let c = unsafe { poll_call(ring, r, ep, &[sensor_read_hdr()]) };
    assert_eq!(done(c), (0, 0), "the owner's listed interface was refused");
}

/// **The kill switch's line through the poller**: a `Gpio::set_dir` the
/// poller runs for the owner on the line CONFIG.INI names is answered
/// `REFUSED`, the driver sees nothing, and the `safety-line` record names the
/// OWNER, not the poller.
///
/// **Canary.** `gpio-safety-guard-canary` (the safety lines are not kept):
/// the set_dir is served `OK` and reaches the driver.
#[test]
fn a_poller_set_dir_on_the_kill_switch_line_is_refused_and_recorded_for_the_owner() {
    struct Pin(u32);
    impl Drop for Pin {
        fn drop(&mut self) {
            azos_config::CFG_ESTOP_GPIO_PIN.store(self.0, Ordering::SeqCst);
            set_gpio_probe(None);
        }
    }
    let _g = serial();
    let (_s, _p, _f, owner, ring, r) = polled_ring();
    azos_sched::scheduler::shim_set_task_filter(owner, Some(SyscallFilter::disabled()));
    let _pin = Pin(azos_config::CFG_ESTOP_GPIO_PIN.swap(4, Ordering::SeqCst));
    BOARD_OPS.lock().unwrap().clear();
    set_gpio_probe(Some(board_probe));
    let ep = grant_ep(owner, azos_devif::key::GPIO, azos_devif::gpio::badge(0, 4), CapPerms::RW, 0);
    let op = azos_devif::GpioIdl::OP_SET_DIR;
    let c = unsafe { poll_call(ring, r, ep, &[gpio_hdr(op), azos_devif::gpio::DIR_OUTPUT as u64]) };
    assert_eq!(done(c), (0, 0));
    assert_eq!(unsafe { window(ring, 0) }[1], azos_devif::outcome::REFUSED as u64, "the kill switch's line was set");
    assert_eq!(*BOARD_OPS.lock().unwrap(), vec![], "the driver saw an op on the kill switch's line");
    let mut subjects = Vec::new();
    azos_decision::for_each(|rec| {
        if rec.rule == azos_decision::Rule::SafetyLine as u8 && rec.n == [0, 4, op as u64] {
            subjects.push(rec.subject);
        }
    });
    assert!(subjects.contains(&owner), "no safety-line record names the owner: {subjects:?}");
    assert!(!subjects.contains(&POLLER_TID), "a safety-line record names the poller");
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! A driver with a threaded, level-triggered interrupt, run through the
//! public `lx_emul` API only, over a fake of the kernel's mask-until-ACK
//! line.
//!
//! The shape is i2c-hid's (`drivers/hid/i2c-hid/i2c-hid-core.c`), the HID
//! transport of most I2C touchpads and touchscreens:
//!
//! * the probe requests the line with a NULL primary and a thread function,
//!   `IRQF_TRIGGER_LOW | IRQF_ONESHOT | IRQF_NO_AUTOEN`, then
//!   `enable_irq`s it when it registers the HID device;
//! * the reset command is answered by the device asserting the line; the
//!   probe waits for it with `wait_event_timeout` on a "reset pending" bit;
//! * the thread function reads the input report over I2C (the adapter's
//!   mutex and a transfer that sleeps), which also makes the device release
//!   the line; only then may the line be unmasked;
//! * suspend is `disable_irq`, resume `enable_irq`; a report the device
//!   raises while suspended is read after the resume, not lost;
//! * remove is `free_irq`.
//!
//! The fake kernel is the loop at the bottom: while the device asserts the
//! line and the line is not masked, it masks the line and hands the server
//! one event (`PORT_EVENT_IRQ` → `deliver_irq`); the chip's ACK unmasks it.

use lx_emul::irq::{IrqChip, IrqReturn, IRQF_NO_AUTOEN, IRQF_ONESHOT, IRQF_TRIGGER_LOW};
use lx_emul::lock::{Mutex, WaitQueueHead};
use lx_emul::timer::msecs_to_jiffies;
use lx_emul::Env;
use std::cell::{Cell, RefCell};

const MS: u64 = 1_000_000;
const IRQ: u32 = 37;
const IHID: usize = 0x1d;
/// The device answers the reset command this long after it.
const RESET_LATENCY: u64 = 3 * MS;
/// A report 0 means "reset done" (i2c-hid: an empty input report).
const RESET_REPORT: u8 = 0;

/// The device, the kernel's view of the line, and what the test observes.
struct World {
    /// The device drives the line low (asserted) until its report is read.
    asserted: Cell<bool>,
    /// The kernel masked the line on a delivery; the ACK clears it.
    masked: Cell<bool>,
    /// The report the device holds, and the ones it will raise: (time, id).
    report: Cell<Option<u8>>,
    raises: RefCell<Vec<(u64, u8)>>,
    now: Cell<u64>,
    deliveries: Cell<u32>,
    /// i2c-hid's `ihid->wait` and `I2C_HID_RESET_PENDING`.
    wait: WaitQueueHead,
    reset_pending: Cell<bool>,
    /// The I2C adapter's bus lock.
    bus: Mutex,
    reports: RefCell<Vec<u8>>,
    events: RefCell<Vec<&'static str>>,
}

thread_local! {
    static WORLD: &'static World = Box::leak(Box::new(World {
        asserted: Cell::new(false),
        masked: Cell::new(false),
        report: Cell::new(None),
        raises: RefCell::new(Vec::new()),
        now: Cell::new(0),
        deliveries: Cell::new(0),
        wait: WaitQueueHead::new(),
        reset_pending: Cell::new(false),
        bus: Mutex::new(),
        reports: RefCell::new(Vec::new()),
        events: RefCell::new(Vec::new()),
    }));
}

fn w() -> &'static World {
    WORLD.with(|w| *w)
}
fn now() -> u64 {
    w().now.get()
}
fn event(e: &'static str) {
    w().events.borrow_mut().push(e);
}

fn bind(_: usize, irq: u32) -> i32 {
    assert_eq!(irq, IRQ);
    0
}
fn ack(_: usize, _: u32) {
    w().masked.set(false);
}

/// One I2C transfer: the bus lock, then 1 ms on the wire.
fn i2c_xfer(env: &mut Env) {
    env.mutex_lock(&w().bus).unwrap();
    env.msleep(1).unwrap();
    env.mutex_unlock(&w().bus).unwrap();
}

/// `i2c_hid_irq` → `i2c_hid_get_input`: read the report; the device then
/// releases the line.
fn i2c_hid_irq(env: &mut Env, irq: u32, dev_id: usize) -> IrqReturn {
    assert_eq!((irq, dev_id), (IRQ, IHID));
    assert!(!env.in_atomic(), "the thread function runs in a task");
    i2c_xfer(env);
    let Some(r) = w().report.take() else { return IrqReturn::None };
    w().asserted.set(false);
    if r == RESET_REPORT && w().reset_pending.replace(false) {
        env.wake_up(&w().wait);
    } else {
        w().reports.borrow_mut().push(r);
    }
    IrqReturn::Handled
}

/// `i2c_hid_probe` → `i2c_hid_core_register_hid` → `i2c_hid_hwreset`.
fn probe(env: &mut Env, _: usize) -> i32 {
    let flags = IRQF_TRIGGER_LOW | IRQF_ONESHOT | IRQF_NO_AUTOEN;
    assert_eq!(env.request_threaded_irq(IRQ, None, Some(i2c_hid_irq), flags, "i2c-hid", IHID), 0);
    env.enable_irq(IRQ);
    w().reset_pending.set(true);
    i2c_xfer(env); // the reset command
    w().raises.borrow_mut().push((now() + RESET_LATENCY, RESET_REPORT));
    let left = env.wait_event_timeout(&w().wait, |_| !w().reset_pending.get(), msecs_to_jiffies(5000)).unwrap();
    event(if left > 0 { "reset done" } else { "reset timeout" });
    0
}

/// `i2c_hid_core_suspend`.
fn suspend(env: &mut Env, _: usize) -> i32 {
    env.disable_irq(IRQ).unwrap();
    event("suspended");
    0
}

/// `i2c_hid_core_resume`.
fn resume(env: &mut Env, _: usize) -> i32 {
    env.enable_irq(IRQ);
    event("resumed");
    0
}

/// `i2c_hid_remove`.
fn remove(env: &mut Env, _: usize) -> i32 {
    assert_eq!(env.free_irq(IRQ, IHID), Some("i2c-hid"));
    event("removed");
    0
}

/// The fake kernel and the server loop, until `until` (ns). Bounded, so a
/// storm fails the test instead of hanging it.
fn run(env: &mut Env, until: u64) {
    for pass in 0.. {
        assert!(pass < 10_000, "the loop never went idle (at {} ns)", now());
        // A device raise that is due.
        let due = {
            let mut r = w().raises.borrow_mut();
            r.iter().position(|&(at, _)| at <= now()).map(|i| r.remove(i).1)
        };
        if let Some(id) = due {
            assert!(w().report.replace(Some(id)).is_none(), "a report was overwritten");
            w().asserted.set(true);
        }
        // The kernel: a level line asserted and not masked is delivered.
        if w().asserted.get() && !w().masked.get() {
            w().masked.set(true);
            w().deliveries.set(w().deliveries.get() + 1);
            env.deliver_irq(IRQ);
        }
        let next = env.run_once(now());
        let raise = w().raises.borrow().iter().map(|&(at, _)| at).min();
        let ready = w().asserted.get() && !w().masked.get();
        match [next, raise].into_iter().flatten().min() {
            _ if ready => {}
            Some(t) if t < until => w().now.set(t.max(now())),
            _ => break,
        }
    }
    w().now.set(until.max(now()));
}

#[test]
fn an_i2c_hid_shaped_driver_takes_its_level_interrupt_in_a_thread() {
    let mut env = Box::new(Env::new());
    let mut stacks: Vec<Box<[u8]>> = (0..4).map(|_| vec![0u8; 64 * 1024].into_boxed_slice()).collect();
    for s in stacks.iter_mut() {
        // SAFETY: the stacks outlive the boxed Env, which never moves.
        unsafe { env.add_stack(s.as_mut_ptr(), s.len()).unwrap() };
    }
    env.clock.set_source(now);
    env.set_irq_chip(IrqChip { bind, ack });

    env.kthread_run(probe, 0).unwrap();
    run(&mut env, 20 * MS);
    assert_eq!(*w().events.borrow(), ["reset done"]);

    // Two touches.
    w().raises.borrow_mut().extend([(25 * MS, 1), (30 * MS, 2)]);
    run(&mut env, 40 * MS);
    assert_eq!(*w().reports.borrow(), [1, 2]);

    // Suspend; a touch while suspended stays masked and is read on resume.
    env.kthread_run(suspend, 0).unwrap();
    run(&mut env, 45 * MS);
    w().raises.borrow_mut().push((50 * MS, 3));
    run(&mut env, 60 * MS);
    assert_eq!(*w().reports.borrow(), [1, 2], "nothing runs while disabled");
    assert!(w().masked.get() && w().asserted.get(), "held masked, still asserted");
    env.kthread_run(resume, 0).unwrap();
    run(&mut env, 70 * MS);
    assert_eq!(*w().reports.borrow(), [1, 2, 3]);

    env.kthread_run(remove, 0).unwrap();
    run(&mut env, 80 * MS);
    assert_eq!(*w().events.borrow(), ["reset done", "suspended", "resumed", "removed"]);

    // One delivery per report: no line taken again before the thread read
    // the device, and the suspended one delivered once, then re-raised by
    // the level line after the resume's ACK.
    assert_eq!(w().deliveries.get(), 5);
    let s = env.irqs.stats();
    assert_eq!((s.threads_run, s.unhandled, s.spurious, s.misuse, s.bad_wakes), (4, 0, 0, 0, 0));
    let st = env.stats();
    assert_eq!((st.would_block, st.atomic_sleeps, st.irq_leaks, st.stack_overflows), (0, 0, 0, 0));
    assert_eq!(env.tasks.count(), 0, "the irq thread exited");
    drop(env);
    drop(stacks);
}

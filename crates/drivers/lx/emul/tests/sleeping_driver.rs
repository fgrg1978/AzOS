// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! A driver that sleeps, run through the public `lx_emul` API only.
//!
//! No Linux driver in the tree can run on the layer yet: `lxbase.ko` and
//! `xz_dec.ko` never sleep, and the filesystem set that does (`jbd2`'s
//! journal thread, `ext4`'s waits) is built but not loaded. The first real
//! user of the stackful tasks is the lx-subdev-pilot: a camera sensor whose
//! power-on sequence sleeps between steps (imx219: `usleep_range` after
//! releasing reset, before the first I2C access). This module has the same
//! shape, so the sequence a sensor probe needs is exercised end to end:
//!
//! * module init runs in a kernel thread (the `insmod` context), registers
//!   the driver and adds the device; the probe runs in that thread;
//! * the probe takes the I2C adapter mutex, powers the sensor up with a
//!   `usleep_range`, reads the chip id and queues the stream-on work;
//! * the work item `msleep`s for the PLL to lock, then waits with
//!   `wait_event_timeout` for the first frame interrupt;
//! * the frame interrupt (the CSI-2 receiver's, requested by the probe with
//!   `request_irq`) arrives as a port notification (here: the loop below)
//!   and the handler runs in hard-interrupt context through `deliver_irq`;
//! * a kernel thread polls a status register with `msleep` until
//!   `kthread_stop`, which the module exit calls from a task.
//!
//! The loop at the bottom is the server's: block until the deadline
//! `run_once` returns or until a notification arrives, whichever is first.

use lx_emul::irq::{IrqChip, IrqReturn, IRQF_TRIGGER_RISING};
use lx_emul::lock::{Mutex, WaitQueueHead};
use lx_emul::device::{DeviceHandle, DeviceInfo, Driver};
use lx_emul::lock::TaskId;
use lx_emul::timer::msecs_to_jiffies;
use lx_emul::workqueue::WorkHandle;
use lx_emul::Env;
use std::cell::{Cell, RefCell};

const MS: u64 = 1_000_000;
const US: u64 = 1_000;
/// imx219's XCLR (reset release) to first I2C access delay.
const XCLR_DELAY_US: u64 = 6_200;
const CHIP_ID: u16 = 0x0219;
/// When the sensor delivers its first frame (port notification).
const FRAME_IRQ_AT: u64 = 40 * MS;
/// The frame interrupt's Linux irq number (the server's event key).
const FRAME_IRQ: u32 = 7;

/// The sensor's state and what the test observes, one per test thread.
struct Sensor {
    /// The I2C adapter's bus lock (`i2c_adapter.bus_lock`).
    bus: Mutex,
    frame_wq: WaitQueueHead,
    frame_done: Cell<bool>,
    powered_at: Cell<u64>,
    first_i2c_at: Cell<u64>,
    stream_work: Cell<Option<WorkHandle>>,
    poller: Cell<Option<TaskId>>,
    polls: Cell<u32>,
    events: RefCell<Vec<&'static str>>,
}

thread_local! {
    static SENSOR: &'static Sensor = Box::leak(Box::new(Sensor {
        bus: Mutex::new(),
        frame_wq: WaitQueueHead::new(),
        frame_done: Cell::new(false),
        powered_at: Cell::new(0),
        first_i2c_at: Cell::new(0),
        stream_work: Cell::new(None),
        poller: Cell::new(None),
        polls: Cell::new(0),
        events: RefCell::new(Vec::new()),
    }));
    static NOW: Cell<u64> = const { Cell::new(0) };
}

fn sensor() -> &'static Sensor {
    SENSOR.with(|s| *s)
}

fn event(e: &'static str) {
    sensor().events.borrow_mut().push(e);
}

fn now() -> u64 {
    NOW.with(|n| n.get())
}

/// An I2C register read: the adapter lock is held across the transfer.
fn i2c_read16(env: &mut Env, reg: u16) -> u16 {
    let s = sensor();
    env.mutex_lock(&s.bus).unwrap();
    if s.first_i2c_at.get() == 0 {
        s.first_i2c_at.set(env.clock.now_ns());
    }
    let v = if reg == 0x0000 { CHIP_ID } else { 0 };
    env.mutex_unlock(&s.bus).unwrap();
    v
}

fn probe(env: &mut Env, _dev: DeviceHandle) -> i32 {
    let s = sensor();
    // Regulators and clock on, XCLR released, then wait before touching I2C.
    s.powered_at.set(env.clock.now_ns());
    env.usleep_range(XCLR_DELAY_US, XCLR_DELAY_US + 10).unwrap();
    if i2c_read16(env, 0x0000) != CHIP_ID {
        return -lx_emul::errno::ENODEV;
    }
    event("probed");
    assert_eq!(env.request_irq(FRAME_IRQ, frame_irq, IRQF_TRIGGER_RISING, "csi-frame", 1), 0);
    let w = env.init_work(stream_on, 0).unwrap();
    s.stream_work.set(Some(w));
    env.queue_work(w).unwrap();
    s.poller.set(env.kthread_run(poll_status, 0));
    0
}

fn stream_on(env: &mut Env, _w: WorkHandle) {
    let s = sensor();
    // PLL lock time.
    env.msleep(5).unwrap();
    event("streaming");
    let left = env.wait_event_timeout(&s.frame_wq, |_| s.frame_done.get(), msecs_to_jiffies(100)).unwrap();
    event(if left > 0 { "first frame" } else { "frame timeout" });
}

fn poll_status(env: &mut Env, _: usize) -> i32 {
    let s = sensor();
    while !env.kthread_should_stop() {
        i2c_read16(env, 0x0018);
        s.polls.set(s.polls.get() + 1);
        env.msleep(20).unwrap();
    }
    event("poller stopped");
    7
}

fn frame_irq(env: &mut Env, _: u32, _: usize) -> IrqReturn {
    let s = sensor();
    s.frame_done.set(true);
    env.wake_up(&s.frame_wq);
    IrqReturn::Handled
}

fn module_init(env: &mut Env, _: usize) -> i32 {
    env.driver_register(Driver { name: "sensor", compatible: &["test,sensor"], probe, remove: None }).unwrap();
    let d = env.device_add(DeviceInfo { name: "sensor0", compatible: Some("test,sensor") }).unwrap();
    if env.devices.bound_driver(d).is_none() {
        return -lx_emul::errno::ENODEV;
    }
    event("init done");
    0
}

fn module_exit(env: &mut Env, _: usize) -> i32 {
    let id = sensor().poller.get().unwrap();
    let code = env.kthread_stop(id).unwrap();
    assert_eq!(code, 7);
    assert_eq!(env.free_irq(FRAME_IRQ, 1), Some("csi-frame"));
    event("exit done");
    0
}

/// The server loop: wait for the deadline or the next notification.
/// Bounded, so a scheduler bug fails the test instead of hanging it.
fn run_until_idle(env: &mut Env, irq_at: &mut Option<u64>, until: u64) {
    let mut t = now();
    for pass in 0.. {
        assert!(pass < 10_000, "the loop never went idle (at {t} ns)");
        NOW.with(|n| n.set(t));
        let next = env.run_once(t);
        match (next, *irq_at) {
            (_, Some(at)) if next.is_none_or(|d| at < d) => {
                *irq_at = None;
                t = at;
                NOW.with(|n| n.set(t));
                env.deliver_irq(FRAME_IRQ);
            }
            (Some(d), _) if d < until => t = d.max(t),
            _ => break,
        }
    }
}

#[test]
fn a_sensor_driver_that_sleeps_probes_streams_and_unloads() {
    let mut env = Box::new(Env::new());
    let mut stacks: Vec<Box<[u8]>> = (0..4).map(|_| vec![0u8; 64 * 1024].into_boxed_slice()).collect();
    for s in stacks.iter_mut() {
        // SAFETY: the stacks outlive the boxed Env, which never moves.
        unsafe { env.add_stack(s.as_mut_ptr(), s.len()).unwrap() };
    }
    env.clock.set_source(now);
    // The server's chip: DEVICE_IRQ_BIND and DEVICE_IRQ_ACK on the line.
    env.set_irq_chip(IrqChip { bind: |_, _| 0, ack: |_, _| {} });
    env.kthread_run(module_init, 0).unwrap();
    let mut irq = Some(FRAME_IRQ_AT);
    run_until_idle(&mut env, &mut irq, 100 * MS);

    let s = sensor();
    assert!(
        s.first_i2c_at.get() - s.powered_at.get() >= XCLR_DELAY_US * US,
        "first I2C access {} ns after power-on",
        s.first_i2c_at.get() - s.powered_at.get()
    );
    assert_eq!(*s.events.borrow(), ["probed", "init done", "streaming", "first frame"]);
    assert!(s.polls.get() >= 4, "the poller ran every 20 ms: {}", s.polls.get());

    env.kthread_run(module_exit, 0).unwrap();
    run_until_idle(&mut env, &mut irq, 200 * MS);
    assert_eq!(s.events.borrow()[4..], ["poller stopped", "exit done"]);

    let st = env.stats();
    assert_eq!((st.would_block, st.atomic_sleeps, st.irq_leaks, st.stack_overflows), (0, 0, 0, 0));
    assert_eq!(st.irqs, 1);
    assert_eq!(env.irqs.stats().acks, 1);
    assert_eq!(env.tasks.count(), 1, "only the parked worker is left");
    drop(env);
    drop(stacks);
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ring-3 GPIO device host: the runtime power of a device served on an
//! endpoint.
//!
//! The driver is a device with a power state (`azos_devif::power::runtime`)
//! and serves `DevicePower` on the endpoint its row grants (a thread of its
//! own): the power service sets its idle timeout, takes wakelocks and reads
//! its records. The server answers an op only when the badge of the call
//! carries its class (`runtime::classes_of`). The driver's topology row grants
//! that endpoint (`endpoint.pm-gpio`, `READ`); in a topology without the row
//! the thread finds nothing to accept and the driver never autosuspends. A
//! request resumes a suspended driver before it is handled. This driver has no
//! hardware, so its suspend and resume gate nothing but its own state (a flag,
//! and a console line for each transition): the transitions, the idle clock,
//! the ledger and the records are real and exercised, and the hook where a real
//! controller's clock gate goes is `Gate`. The main thread runs the idle clock.

#![no_std]
#![no_main]


use azos_libsys as sys;
use sys::dev::MsgDesc;

/// The runtime power core of this driver's device (`azos_devif::power::runtime`).
type Pm = sys::dev::power::runtime::RuntimePm;

/// Wait before accepting again after the endpoint answered nothing (a row
/// that grants none): the thread costs one wake-up a period, not a spin.
const ACCEPT_RETRY_MS: u64 = 1_000;

/// The controller as the runtime PM core powers it down and up.
struct Gate {
    gated: bool,
}

impl sys::dev::power::runtime::PmDevice for Gate {
    fn suspend(&mut self) -> bool {
        self.gated = true;
        sys::println(b"[gpio_drv] pm: suspended");
        true
    }
    fn resume(&mut self) -> bool {
        self.gated = false;
        sys::println(b"[gpio_drv] pm: resumed");
        true
    }
}

/// What the idle clock and the endpoint thread share.
struct State {
    pm: Pm,
    gate: Gate,
}

/// What the two threads share.
static SHARED: sys::Lock<Option<State>> = sys::Lock::new(None);

/// Run `f` on the shared state. Spins (yielding) while the other thread has
/// it: its critical sections are a few instructions long.
fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let r = SHARED.lock().as_mut().map(f);
    r.expect("gpio_drv: state used before it was set up")
}

/// The PM clock: the vDSO's. 0 when the kernel publishes none, which leaves
/// the idle timeout unable to run out (the driver then never autosuspends).
fn now_ns() -> u64 {
    sys::vdso_now_ns()
}

/// The endpoint thread's stack.
#[repr(C, align(16))]
struct Stack([u8; 8192]);
static mut PM_STACK: Stack = Stack([0; 8192]);

/// Serve `DevicePower` on the endpoint the row grants, for ever.
extern "C" fn pm_thread(_: u64, _: u64, _: u64) -> ! {
    loop {
        let mut req = MsgDesc::default();
        let call = sys::ipc_accept_v2(&mut req);
        if call < 0 {
            // No endpoint granted (a topology without the row), or a spurious wake: look again later.
            sys::sleep(ACCEPT_RETRY_MS);
            continue;
        }
        let mut rep = MsgDesc::default();
        with(|st| {
            let mut srv = sys::dev::power::runtime::PmServer {
                pm: &mut st.pm,
                dev: &mut st.gate,
                now_ns: now_ns(),
                classes: sys::dev::power::runtime::classes_of(&req),
            };
            let _ = sys::dev::power::DevicePowerIdl::dispatch(&mut srv, &req, &mut rep);
        });
        let _ = sys::ipc_reply_v2(call as u64, &rep);
    }
}

/// Longest sleep of the idle clock with nothing timed.
const IDLE_PARK_MS: u64 = 1_000;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let quota = sys::dev::power::runtime::Quota::new(azos_limits::DEVICE_WAKELOCKS as u32, azos_limits::DEVICE_WAKELOCK_TTL_MAX_MS as u32);
    *SHARED.lock() = Some(State { pm: Pm::new(quota, now_ns()), gate: Gate { gated: false } });
    // The stack is the endpoint thread's alone, and its top is 16-aligned.
    let top = core::ptr::addr_of_mut!(PM_STACK) as usize + core::mem::size_of::<Stack>();
    if sys::thread_create(pm_thread, top, 0, core::ptr::null_mut()) < 0 {
        sys::println(b"[gpio_drv] no thread for DevicePower; the driver never autosuspends");
    }
    sys::println(b"[gpio_drv] serving DevicePower");
    loop {
        // Sleep until the idle clock or a wakelock is due, at most the park.
        let ms = with(|st| {
            st.pm.tick(&mut st.gate, now_ns());
            st.pm.next_deadline_ns().map_or(IDLE_PARK_MS, |d| d.saturating_sub(now_ns()).div_ceil(1_000_000).clamp(1, IDLE_PARK_MS))
        });
        sys::sleep(ms);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(2);
}

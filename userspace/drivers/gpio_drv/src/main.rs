// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! E11.AQ3 — ring-3 userspace GPIO driver.
//!
//! Registers itself as the handler for `DRV_KIND_GPIO` with the kernel
//! driver-server, then serves requests that the in-kernel
//! `UserDriverProxy` forwards: fetch → handle → reply. This is the proof that
//! a driver can run as an ordinary user process, with the kernel routing
//! `SYS_DRV_INVOKE` calls to it over the driver-server request/reply queues.
//!
//! The op handled here (`GPIO_OP_PING`) returns a fixed identifier plus an
//! echo of the first input byte, which is enough to prove the round-trip
//! end-to-end in QEMU. A production driver would additionally map the GPIO
//! controller's MMIO window (`DOMAIN_MMIO_MAP`) and read/write the pin registers — the same
//! serve loop, only with a real device access in the handler.
//!
//! **Runtime power management.** The driver is a device with a power state
//! (`azos_devif::power::runtime`) and serves `DevicePower` on the endpoint its
//! row grants (a second thread, as `buzz_drv`): the power service sets its
//! idle timeout, takes wakelocks and reads its records. The server answers an
//! op only when the badge of the call carries its class
//! (`runtime::classes_of`). The driver's topology row grants that endpoint
//! (`endpoint.pm-gpio`, `READ`); in a topology without the row the thread finds
//! nothing to accept and the driver never autosuspends. A request resumes a
//! suspended driver before it is handled. This driver has no hardware, so its
//! suspend and resume gate nothing but its own state (a flag, and a console
//! line for each transition): the transitions, the idle clock, the ledger and
//! the records are real and exercised, and the hook where a real controller's
//! clock gate goes is `Gate`.

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use azos_libsys as sys;
use sys::dev::MsgDesc;

/// The runtime power core of this driver's device (`azos_devif::power::runtime`).
type Pm = sys::dev::power::runtime::RuntimePm;

// ── Wire constants + structs — MUST byte-match azos_driver_server ───────
// (the structs are mirrored here so this excluded crate stays free of kernel
//  deps; both sides are `#[repr(C)]` so the layout is identical).
//
// The KIND is no longer mirrored. It moved to `crates/core/abi` on 2026-09-06 —
// dependency-free, and the crate that defines every other number this program
// puts in a register — so the one constant that decides WHICH DEVICE this
// program claims is now read from the same place the kernel reads it.
use azos_abi::drv_kind::DRV_KIND_GPIO;
const REQ_PAYLOAD_BYTES: usize = 64;
const REPLY_PAYLOAD_BYTES: usize = 64;

/// Op: liveness ping — reply carries [`PING_REPLY_TAG`, echo(input[0])].
const GPIO_OP_PING: u32 = 0;
/// Identifier the kernel smoke checks to confirm the reply came from us.
const PING_REPLY_TAG: u8 = 0xA5;
/// Reply status: success.
const STATUS_OK: i32 = 0;
/// Reply status: unknown op.
const STATUS_BAD_OP: i32 = -1;
/// Pause after a call the kernel refused with nothing done (the reply is
/// still owed), so a persistent refusal does not spin.
const REFUSED_RETRY_MS: u64 = 10;

#[derive(Clone, Copy)]
#[repr(C)]
struct DriverRequest {
    token: u64,
    client_tid: u32,
    op: u32,
    in_len: u16,
    out_cap: u16,
    input: [u8; REQ_PAYLOAD_BYTES],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct DriverReply {
    token: u64,
    status: i32,
    out_len: u16,
    _pad: u16,
    output: [u8; REPLY_PAYLOAD_BYTES],
}

impl DriverRequest {
    const fn zeroed() -> Self {
        DriverRequest {
            token: 0,
            client_tid: 0,
            op: 0,
            in_len: 0,
            out_cap: 0,
            input: [0; REQ_PAYLOAD_BYTES],
        }
    }
}

impl DriverReply {
    const fn zeroed() -> Self {
        DriverReply {
            token: 0,
            status: 0,
            out_len: 0,
            _pad: 0,
            output: [0; REPLY_PAYLOAD_BYTES],
        }
    }
}

/// Build the reply for one request.
fn handle(req: &DriverRequest) -> DriverReply {
    let mut reply = DriverReply::zeroed();
    reply.token = req.token; // the proxy matches reply → waiter by token
    match req.op {
        GPIO_OP_PING => {
            reply.status = STATUS_OK;
            reply.output[0] = PING_REPLY_TAG;
            reply.output[1] = if req.in_len > 0 { req.input[0] } else { 0 };
            reply.out_len = 2;
        }
        _ => {
            reply.status = STATUS_BAD_OP;
            reply.out_len = 0;
        }
    }
    reply
}

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

/// What the serve loop and the endpoint thread share.
struct State {
    pm: Pm,
    gate: Gate,
}

struct Shared {
    lock: AtomicBool,
    state: UnsafeCell<Option<State>>,
}
// SAFETY: `state` is touched only with `lock` held (`with`).
unsafe impl Sync for Shared {}

static SHARED: Shared = Shared { lock: AtomicBool::new(false), state: UnsafeCell::new(None) };

/// Run `f` on the shared state. Spins (yielding) while the other thread has
/// it: its critical sections are a few instructions long.
fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    while SHARED.lock.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }
    // SAFETY: the lock is held.
    let r = unsafe { (*SHARED.state.get()).as_mut().map(f) };
    SHARED.lock.store(false, Ordering::Release);
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

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Register through the TYPED path (`DOMAIN_DRIVER_REGISTER`, 556).
    //
    // Two calls instead of one, and the pair is the point. `cap_lookup` asks
    // the kernel which handle names the DriverRegistry capability this task
    // already holds — the topology grants it `drv.1` at boot — and
    // `drv_srv_register_typed` takes only that handle. There is no `kind`
    // argument anywhere in the sequence, so this program cannot ask to be the
    // motor driver even by mistake: the kind is read out of the capability.
    //
    // The untyped `drv_srv_register(DRV_KIND_GPIO, ...)` this replaces still
    // exists and still works; what it cannot do is stop a caller from naming
    // a device, only refuse it afterwards.
    //
    // **No fallback to the untyped call on failure, deliberately.** A silent
    // fallback would make the typed path untestable: the QEMU scenario would
    // stay green whether or not 556 works, which is exactly the shape of
    // green this migration exists to stop.
    let cap = sys::cap_lookup(sys::ty::DRIVER_REGISTRY.raw(), DRV_KIND_GPIO);
    if cap < 0 {
        sys::println(b"[gpio_drv] no DriverRegistry capability FAILED");
        sys::exit(1);
    }
    if sys::drv_srv_register_typed(cap as u32, 0, 0, 0) != 0 {
        sys::println(b"[gpio_drv] typed register FAILED");
        sys::exit(1);
    }
    sys::println(b"[gpio_drv] registered DRV_KIND_GPIO via Cap<DriverRegistry>, serving");

    // One trap per request: each call posts the reply owed to
    // the previous request, if any, and fetches the next one. With the queue
    // empty the call parks this task until a request is queued (610,
    // `DOMAIN_DRIVER_REPLY_WAIT`), so an idle driver leaves its hart idle
    // instead of polling it; the park is bounded by the kernel (park 0 = its
    // default), and a bound that passes returns -1 to be called again.
    let quota = sys::dev::power::runtime::Quota::new(azos_limits::DEVICE_WAKELOCKS as u32, azos_limits::DEVICE_WAKELOCK_TTL_MAX_MS as u32);
    // SAFETY: no other thread exists yet.
    unsafe {
        *SHARED.state.get() = Some(State { pm: Pm::new(quota, now_ns()), gate: Gate { gated: false } });
    }
    // The stack is the endpoint thread's alone, and its top is 16-aligned.
    let top = core::ptr::addr_of_mut!(PM_STACK) as usize + core::mem::size_of::<Stack>();
    if sys::thread_create(pm_thread, top, 0, core::ptr::null_mut()) < 0 {
        sys::println(b"[gpio_drv] no thread for DevicePower; the driver never autosuspends");
    }

    let mut req = DriverRequest::zeroed();
    let mut reply = DriverReply::zeroed();
    let mut owed = false;
    loop {
        // Park until a request, or until the idle clock or a wakelock is due;
        // with nothing timed, the kernel's default bound.
        let park_ms = with(|st| {
            st.pm.tick(&mut st.gate, now_ns());
            match st.pm.next_deadline_ns() {
                Some(d) => d.saturating_sub(now_ns()).div_ceil(1_000_000).clamp(1, u32::MAX as u64) as u32,
                None => 0,
            }
        });
        let reply_ptr = if owed {
            &reply as *const DriverReply as *const u8
        } else {
            core::ptr::null()
        };
        let rc = sys::drv_srv_reply_wait(
            DRV_KIND_GPIO,
            reply_ptr,
            &mut req as *mut DriverRequest as *mut u8,
            park_ms,
        );
        match rc {
            0 => {
                // A use resumes a suspended driver first; one that cannot be
                // resumed does not serve (the proxy sees the bad-op status).
                let served = with(|st| {
                    let t = now_ns();
                    let ok = st.pm.on_use(&mut st.gate, t).is_ok();
                    st.pm.idle(now_ns());
                    ok
                });
                reply = if served {
                    handle(&req)
                } else {
                    let mut r = DriverReply::zeroed();
                    r.token = req.token;
                    r.status = STATUS_BAD_OP;
                    r
                };
                owed = true;
            }
            // The reply went out; the park ended with no request.
            -1 => owed = false,
            // Refused with nothing done: the reply is still owed.
            _ => sys::sleep(REFUSED_RETRY_MS),
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(2);
}

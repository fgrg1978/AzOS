// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! E11.AQ3 — ring-3 userspace GPIO driver.
//!
//! Registers itself as the handler for `DRV_KIND_GPIO` with the kernel
//! driver-server (RFC-0002), then serves requests that the in-kernel
//! `UserDriverProxy` forwards: fetch → handle → reply. This is the proof that
//! a driver can run as an ordinary user process, with the kernel routing
//! `SYS_DRV_INVOKE` calls to it over the driver-server request/reply queues.
//!
//! The op handled here (`GPIO_OP_PING`) returns a fixed identifier plus an
//! echo of the first input byte, which is enough to prove the round-trip
//! end-to-end in QEMU. A production driver would additionally map the GPIO
//! controller's MMIO window (`SYS_MMIO_MAP`) and read/write the pin registers — the same
//! serve loop, only with a real device access in the handler.

#![no_std]
#![no_main]

use azos_libsys as sys;

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

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Register through the TYPED path (`SYS_DRIVER_REGISTER_TYPED`, 556).
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
    let cap = sys::cap_lookup(sys::CapKind::DriverRegistry as u8, DRV_KIND_GPIO);
    if cap < 0 {
        sys::println(b"[gpio_drv] no DriverRegistry capability FAILED");
        sys::exit(1);
    }
    if sys::drv_srv_register_typed(cap as u32, 0, 0, 0) != 0 {
        sys::println(b"[gpio_drv] typed register FAILED");
        sys::exit(1);
    }
    sys::println(b"[gpio_drv] registered DRV_KIND_GPIO via Cap<DriverRegistry>, serving");

    // One trap per request (RFC-0041 §D): each call posts the reply owed to
    // the previous request, if any, and fetches the next one. With the queue
    // empty the call parks this task until a request is queued (610,
    // `SYS_DRIVER_REPLY_WAIT`), so an idle driver leaves its hart idle
    // instead of polling it; the park is bounded by the kernel (park 0 = its
    // default), and a bound that passes returns -1 to be called again.
    let mut req = DriverRequest::zeroed();
    let mut reply = DriverReply::zeroed();
    let mut owed = false;
    loop {
        let reply_ptr = if owed {
            &reply as *const DriverReply as *const u8
        } else {
            core::ptr::null()
        };
        let rc = sys::drv_srv_reply_wait(
            DRV_KIND_GPIO,
            reply_ptr,
            &mut req as *mut DriverRequest as *mut u8,
            0,
        );
        match rc {
            0 => {
                reply = handle(&req);
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

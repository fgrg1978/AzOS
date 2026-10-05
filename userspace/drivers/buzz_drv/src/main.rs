// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ring-3 piezo buzzer driver (RFC-0040 rule 3): the ring-3 host of
//! `crates/drivers/buzzer` (Kconfig `DRV_BUZZER_PLACEMENT = ring3`).
//!
//! Started by the kernel at boot (`ring3_driver_launch_task`), with the
//! capabilities of its own topology row, `BUZZDRV.ELF`: `DriverRegistry` for
//! `DRV_KIND_BUZZER` and `Pwm` READ|WRITE on its one channel. The PWM
//! controller itself stays in the kernel (rule 1): this program reaches it
//! only through the typed `Cap<Pwm>` calls, which the kernel checks per
//! channel and refuses on any motor-bound channel.
//!
//! Every op is answered BEFORE the sound finishes: `SYS_BUZZER_TONE` returns
//! once the tone has started. A tone, a beep or a pattern is a list of steps
//! the loop plays against the vDSO clock, so the kernel caller
//! (`UserDriverProxy`, 100 ms reply timeout) never waits for a melody. A new
//! request replaces whatever is playing.
//!
//! The loop waits in `SYS_DRIVER_REPLY_WAIT` (610): parked until a request is
//! queued, or until the current step is due while something plays. Silent and
//! idle, it wakes only at the kernel's park bound.

#![no_std]
#![no_main]

use azos_abi::drv_kind::DRV_KIND_BUZZER;
use azos_buzzer::{serve, Player, Pwm, BUZZER_PWM_CHANNEL, SOURCE_MARKER};
use azos_libsys as sys;

/// Pause after a call the kernel refused with nothing done (the reply is
/// still owed), so a persistent refusal does not spin.
const REFUSED_RETRY_MS: u64 = 10;

/// The monotonic clock in milliseconds (vDSO), or `None` when the kernel
/// publishes no clock (the page reads 0).
fn clock_ms() -> Option<u64> {
    match sys::vdso_now_ns() {
        0 => None,
        ns => Some(ns / 1_000_000),
    }
}

/// The buzzer's channel through the typed `Cap<Pwm>` calls, which the kernel
/// checks per channel (and refuses on any motor-bound one).
struct CapPwm(u32);

impl Pwm for CapPwm {
    fn set_period_ns(&mut self, period_ns: u32) -> bool {
        sys::pwm_set_period_typed(self.0, period_ns) >= 0
    }
    fn set_duty_pct(&mut self, pct: u32) -> bool {
        sys::pwm_set_duty_pct_typed(self.0, pct) >= 0
    }
    fn enable(&mut self) -> bool {
        sys::pwm_enable_typed(self.0) >= 0
    }
    fn disable(&mut self) -> bool {
        sys::pwm_disable_typed(self.0) >= 0
    }
}

// Wire structs, byte-identical to `azos_driver_server`'s (`#[repr(C)]`).
const REQ_PAYLOAD_BYTES: usize = 64;
const REPLY_PAYLOAD_BYTES: usize = 64;

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

const STATUS_OK: i32 = 0;
const STATUS_BAD_OP: i32 = -1;

fn handle(req: &DriverRequest, p: &mut Player, pwm: &mut CapPwm) -> DriverReply {
    let mut reply = DriverReply {
        token: req.token,
        status: STATUS_OK,
        out_len: 1,
        _pad: 0,
        output: [0; REPLY_PAYLOAD_BYTES],
    };
    let n = (req.in_len as usize).min(REQ_PAYLOAD_BYTES);
    let ok = match serve(p, pwm, req.op, &req.input[..n]) {
        Some(ok) => ok,
        None => {
            reply.status = STATUS_BAD_OP;
            false
        }
    };
    // The proxy returns the payload, not `status`: byte 0 is the verdict.
    reply.output[0] = ok as u8;
    reply
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let pwm = sys::cap_lookup(sys::CapKind::Pwm as u8, BUZZER_PWM_CHANNEL);
    if pwm < 0 {
        sys::println(b"[buzzdrv] FAILED: no Cap<Pwm> for the buzzer channel");
        sys::exit(1);
    }
    let reg = sys::cap_lookup(sys::CapKind::DriverRegistry as u8, DRV_KIND_BUZZER);
    if reg < 0 {
        sys::println(b"[buzzdrv] FAILED: no DriverRegistry capability");
        sys::exit(1);
    }
    let mut pwm = CapPwm(pwm as u32);
    let mut p = Player::new();
    // Silent before serving, as the in-kernel `buzzer_init` left it.
    p.stop(&mut pwm);
    if sys::drv_srv_register_typed(reg as u32, 0, 0, 0) != 0 {
        sys::println(b"[buzzdrv] FAILED: typed register refused");
        sys::exit(1);
    }
    sys::println(b"[buzzdrv] registered DRV_KIND_BUZZER via Cap<DriverRegistry>, serving");
    // The chip-logic source this host runs (`tools/chip_source_check.py`).
    sys::print(b"[buzzdrv] ");
    sys::println(&SOURCE_MARKER);

    let mut req = DriverRequest {
        token: 0, client_tid: 0, op: 0, in_len: 0, out_cap: 0,
        input: [0; REQ_PAYLOAD_BYTES],
    };
    let mut reply = DriverReply {
        token: 0, status: 0, out_len: 0, _pad: 0, output: [0; REPLY_PAYLOAD_BYTES],
    };
    let mut owed = false;
    let mut last_ms = clock_ms().unwrap_or(0);
    loop {
        let reply_ptr = if owed { &reply as *const DriverReply as *const u8 } else { core::ptr::null() };
        let park = p.park_ms();
        let rc = sys::drv_srv_reply_wait(
            DRV_KIND_BUZZER,
            reply_ptr,
            &mut req as *mut DriverRequest as *mut u8,
            park,
        );
        // The time the call took is played BEFORE the request is handled: a
        // park ends early on a request, and a request that does not replace
        // the sound (an unknown op) must not stretch the step.
        let elapsed = match clock_ms() {
            Some(t) => {
                let e = t.saturating_sub(last_ms);
                last_ms = t;
                e.min(u32::MAX as u64) as u32
            }
            // No clock: a park that ran to its end is the only time known.
            None if rc == -1 => park,
            None => 0,
        };
        p.elapse(&mut pwm, elapsed);
        match rc {
            0 => {
                reply = handle(&req, &mut p, &mut pwm);
                owed = true;
            }
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

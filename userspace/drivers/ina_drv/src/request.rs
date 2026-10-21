// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The monitor's request path, without a syscall in it: the wire structs of
//! `azos_driver_server`, and the order in which a proxied request is
//! answered while the chip has a power state (`tests/host/power-tests` pulls
//! this file in by path and drives it with a scripted monitor).
//!
//! The rule it holds: a request is answered from the chip's state AFTER the
//! use, never before it. A suspended chip is resumed and re-measured first; a
//! chip that could not be resumed answers the failure status and nothing
//! else, never the sample taken before the pause.

pub const REQ_PAYLOAD_BYTES: usize = 64;
pub const REPLY_PAYLOAD_BYTES: usize = 64;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct DriverRequest {
    pub token: u64,
    pub client_tid: u32,
    pub op: u32,
    pub in_len: u16,
    pub out_cap: u16,
    pub input: [u8; REQ_PAYLOAD_BYTES],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct DriverReply {
    pub token: u64,
    pub status: i32,
    pub out_len: u16,
    pub _pad: u16,
    pub output: [u8; REPLY_PAYLOAD_BYTES],
}

pub const STATUS_OK: i32 = 0;
/// The request cannot be served: an op the chip logic does not know, or a
/// chip that could not be brought out of its power-down state.
pub const STATUS_BAD_OP: i32 = -1;

impl DriverReply {
    /// A reply to `req` that carries `status` and no data.
    pub fn empty(req: &DriverRequest, status: i32) -> DriverReply {
        DriverReply { token: req.token, status, out_len: 0, _pad: 0, output: [0; REPLY_PAYLOAD_BYTES] }
    }
}

/// The monitor as the request path drives it.
pub trait Unit {
    /// A use is about to be served: resume the chip if it is suspended and
    /// start its idle clock. `Some(true)`: it was resumed; `Some(false)`: it
    /// was running; `None`: it could not be resumed.
    fn begin(&mut self) -> Option<bool>;
    /// The chip is running again after a pause: take a fresh sample.
    fn woke(&mut self);
    /// The reply the chip logic gives `req` from the sample it holds now.
    fn serve(&self, req: &DriverRequest) -> DriverReply;
    /// The request is served: the idle clock starts.
    fn done(&mut self);
}

/// Answer one proxied request.
pub fn answer<U: Unit>(unit: &mut U, req: &DriverRequest) -> DriverReply {
    match unit.begin() {
        Some(true) => unit.woke(),
        Some(false) => {}
        None => return DriverReply::empty(req, STATUS_BAD_OP),
    }
    let reply = unit.serve(req);
    unit.done();
    reply
}

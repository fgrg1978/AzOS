// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `ECHO.ELF`: serves `endpoint.echo`. Replies with its first word plus
//! one and the other three unchanged. While it works on a request it runs
//! at the endpoint's priority ceiling.

use azos_libsys::{self as sys, FastRequest};

pub extern "C" fn main(_region: usize, _info: usize) -> ! {
    let mut req = accept();
    loop {
        let w = req.words;
        req = match sys::fast_ipc_reply_accept(req.handle, [w[0].wrapping_add(1), w[1], w[2], w[3]]) {
            Ok(Some(next)) => next,
            // The reply went out (or went nowhere) with no request to take:
            // take the next one the plain way.
            _ => accept(),
        };
    }
}

/// Block for the next request on any endpoint this task serves.
fn accept() -> FastRequest {
    loop {
        if let Some(r) = sys::fast_ipc_accept_req() {
            return r;
        }
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `ECHO.ELF`: serves `endpoint.echo`. Replies with its first word plus
//! one and the other three unchanged. While it works on a request it runs
//! at the endpoint's priority ceiling.

use super::sys;

pub extern "C" fn main(_region: usize, _info: usize) -> ! {
    let mut req = sys::accept();
    loop {
        let w = req.words;
        req = sys::reply_accept(req.handle, [w[0].wrapping_add(1), w[1], w[2], w[3]]);
    }
}

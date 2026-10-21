// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `input`: take the keyboard and the pointer from the shell (Kconfig
//! `INPUTD`), a client of the `Input` interface (`azos_devif::input`) that
//! `INPUTD.ELF` serves.
//!
//! ```text
//! input watch [-n COUNT]
//! input status
//! input sak
//! ```
//!
//! `watch` asks for the focus, which makes this tool the one task the input
//! drivers' stream is delivered to, and prints each event it reads from the
//! ring the server lends it: `key 103 down`, `btn 272 up`, `rel 0 -3`,
//! `abs 1 16384`. A key that makes a console byte is printed too, and is still
//! typed on the console: the terminal server keeps the console's keys. It ends
//! after `COUNT` events, when the focus moves (the server closes the ring: a
//! later `input watch`, or Ctrl+Alt+Delete, took it), or when stopped, and
//! gives the focus back through its warrant when it ends by itself. Ctrl+Alt+
//! Delete is never printed: it takes the focus and ends the watch, `sak`
//! shows it was counted.
//!
//! `status` prints the server's counters and the generation that holds the
//! focus. `sak` prints how many times the Secure Attention Key was pressed and
//! when, read from the page the server lends read-only.
//!
//! The tool's authority is its row's call right on `endpoint.input` and
//! nothing else. It maps the ring it is lent and sleeps between looks at it, as
//! the drivers' stream offers no wake-up for a reader.

use super::{fail, put, put_num};
use azos_devif::input::{EventRing, TrustedPage, RING_SLOTS};
use azos_devif::{InputCall, InputClient};
use azos_input_wire::event::*;
use azos_libsys as sys;
use azos_libsys::dev::Ep;
use azos_rings::region::{RingStep, SpscRing};

/// Milliseconds between two looks at an empty ring.
const POLL_MS: u64 = 20;

type Client = InputClient<Ep>;

/// The call right on `endpoint.input`: the one `WRITE` capability of this row
/// that answers the Input object's `status`. (With Kconfig `COMPOSITOR` the row
/// holds a second call right, on the compositor's endpoint; both are unbadged
/// `WRITE` grants of a task-hosted endpoint, so the interface tells them apart:
/// the other server refuses a call of another interface.)
fn connect() -> Option<Client> {
    use azos_abi::cap::CapPerms;
    // The pool index of the endpoint is the kernel's (at most 255 endpoints).
    (0..256u32).find_map(|i| {
        let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), i);
        if h <= 0 {
            return None;
        }
        let info = sys::cap_info(h as u32).ok()?;
        if info.rights & CapPerms::WRITE.bits() == 0 {
            return None;
        }
        let c = InputClient::new(Ep(h as u32));
        matches!(c.status(), Ok(o) if o.is_ok()).then_some(c)
    })
}

/// Write the parts; the first error (negative), else 0.
fn text(fd: u64, parts: &[&[u8]]) -> isize {
    let mut rc = 0;
    for p in parts {
        let r = put(fd, p);
        if r < 0 && rc == 0 {
            rc = r;
        }
    }
    rc
}

/// A signed number in decimal.
fn put_signed(fd: u64, v: i32) {
    if v < 0 {
        let _ = put(fd, b"-");
    }
    put_num(fd, v.unsigned_abs() as u64);
}

/// One event as a line, the way `watch` prints it; the result of the writes
/// (negative: the output is gone or the tool was stopped).
fn show(word: u64) -> isize {
    let (ty, code, value) = unpack(word);
    match ty {
        EV_KEY if code >= BTN_MOUSE => {
            text(1, &[b"btn "]);
            put_num(1, code as u64);
            text(1, &[if value == 0 { b" up" } else { b" down" }]);
        }
        EV_KEY => {
            text(1, &[b"key "]);
            put_num(1, code as u64);
            text(1, &[match value {
                0 => b" up",
                2 => b" repeat",
                _ => b" down",
            }]);
        }
        EV_REL => {
            text(1, &[b"rel "]);
            put_num(1, code as u64);
            text(1, &[b" "]);
            put_signed(1, value as i32);
        }
        EV_ABS => {
            text(1, &[b"abs "]);
            put_num(1, code as u64);
            text(1, &[b" "]);
            put_num(1, value as u64);
        }
        _ => {
            text(1, &[b"ev "]);
            put_num(1, ty as u64);
            text(1, &[b" "]);
            put_num(1, code as u64);
        }
    }
    text(1, &[b"\n"])
}

fn refused(op: &[u8], code: u32) -> i32 {
    text(2, &[b"input: ", op, b" refused (outcome "]);
    put_num(2, code as u64);
    text(2, &[b")\n"]);
    1
}

fn unreachable_server() -> i32 {
    fail(b"input", b"the input server did not answer");
    1
}

const WATCH_USAGE: &[u8] = b"usage: input watch [-n COUNT]";

fn watch(c: &mut Client) -> i32 {
    let mut limit = u64::MAX;
    let mut i = 2;
    while i < sys::argc() {
        match sys::arg(i).unwrap_or(b"") {
            b"-n" => {
                i += 1;
                let n = sys::arg(i).and_then(super::parse_u64);
                match n {
                    Some(n) if n > 0 => limit = n,
                    _ => {
                        fail(b"input", WATCH_USAGE);
                        return 2;
                    }
                }
            }
            _ => {
                fail(b"input", WATCH_USAGE);
                return 2;
            }
        }
        i += 1;
    }
    let lease = match c.take_focus() {
        Err(_) => return unreachable_server(),
        Ok(o) if !o.is_ok() => return refused(b"take_focus", o.code),
        Ok(o) => o.value,
    };
    let (Some(ring_cap), Some(warrant)) = (lease.ring.get(), lease.warrant.get()) else {
        fail(b"input", b"the server lent no ring or no warrant");
        return 1;
    };
    let va = sys::shm_map_typed(ring_cap.raw());
    if va <= 0 {
        fail(b"input", b"the event ring cannot be mapped");
        return 1;
    }
    let ring = SpscRing { base: va as usize, cap: RING_SLOTS };
    text(1, &[b"input: focus granted, generation "]);
    put_num(1, lease.generation as u64);
    text(1, &[b"\n"]);
    let (mut seen, mut drops) = (0u64, EventRing::drops(ring.base));
    let mut code = 0;
    'look: loop {
        // Read before looking: events published before the close are in the
        // ring when the close is seen, so a last drain after it takes all.
        let closed = EventRing::closed(ring.base);
        loop {
            let (step, w) = ring.try_pop();
            if step == RingStep::Blocked {
                break;
            }
            let w = show(w);
            if w < 0 {
                code = if w == sys::E_INTR { 130 } else { 1 };
                break 'look;
            }
            seen += 1;
            if seen >= limit {
                break 'look;
            }
        }
        let d = EventRing::drops(ring.base);
        if d != drops {
            text(1, &[b"input: events were dropped, keys and buttons may be out of step\n"]);
            drops = d;
        }
        if closed {
            text(1, &[b"input: focus lost\n"]);
            return code;
        }
        if let sys::SleepResult::Refused(rc) = sys::sleep_until_ns(sys::vdso_now_ns() + POLL_MS * 1_000_000) {
            code = if rc == sys::E_INTR { 130 } else { 1 };
            break;
        }
    }
    // Ended here, not by the server: give the focus back through the warrant.
    let mut w = InputClient::new(Ep(warrant.raw()));
    let _ = w.release();
    code
}

fn status(c: &mut Client) -> i32 {
    let s = match c.status() {
        Err(_) => return unreachable_server(),
        Ok(o) if !o.is_ok() => return refused(b"status", o.code),
        Ok(o) => o.value,
    };
    text(1, &[b"holder "]);
    put_num(1, s.holder as u64);
    text(1, &[b" grants "]);
    put_num(1, s.grants as u64);
    text(1, &[b" sak "]);
    put_num(1, s.sak as u64);
    text(1, &[b" events "]);
    put_num(1, s.events);
    text(1, &[b" lost "]);
    put_num(1, s.lost as u64);
    text(1, &[b" refused "]);
    put_num(1, s.refused as u64);
    text(1, &[b" pending "]);
    put_num(1, s.pending as u64);
    text(1, &[b"\n"]);
    0
}

fn sak(c: &mut Client) -> i32 {
    let lease = match c.trusted() {
        Err(_) => return unreachable_server(),
        Ok(o) if !o.is_ok() => return refused(b"trusted", o.code),
        Ok(o) => o.value,
    };
    let Some(page) = lease.page.get() else {
        fail(b"input", b"the server lent no trusted-path page");
        return 1;
    };
    let va = sys::shm_map_typed(page.raw());
    if va <= 0 {
        fail(b"input", b"the trusted-path page cannot be mapped");
        return 1;
    }
    let count = TrustedPage::count(va as usize);
    text(1, &[b"sak "]);
    put_num(1, count as u64);
    if count != 0 {
        text(1, &[b" last at "]);
        put_num(1, TrustedPage::at_ns(va as usize));
        text(1, &[b" ns"]);
    }
    text(1, &[b"\n"]);
    0
}

/// `input <watch|status|sak> ...`: an exit code.
pub fn run() -> i32 {
    let sub = sys::arg(1).unwrap_or(b"");
    if !matches!(sub, b"watch" | b"status" | b"sak") {
        fail(b"input", b"usage: input watch [-n COUNT] | status | sak");
        return 2;
    }
    let Some(mut c) = connect() else {
        fail(b"input", b"this row holds no call right on the input server (Kconfig INPUTD)");
        return 1;
    };
    match sub {
        b"watch" => watch(&mut c),
        b"status" => status(&mut c),
        _ => sak(&mut c),
    }
}

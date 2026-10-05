// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RFC-0040 gap 2 stage 2b — the SERVER half of `endpoint.demo`.
//!
//! `abitest` spawns this image, calls it with `SYS_IPC_FAST_CALL_EP` (582) —
//! fast IPC addressed by a **capability** rather than by a raw TID — and
//! checks the answer. This program is the thing on the other end.
//!
//! The service is deliberately trivial: answer `w0 + 1`. A reply the client
//! can derive from its own request is what separates "the exchange happened"
//! from "the client read zeroed registers or a stale slot" — the two failures
//! a constant reply would flatten into one.
//!
//! # Why this is its own image and not a second mode of `uhello`
//!
//! A ring-3 program's ROLE on an endpoint is its capability permission —
//! `READ` serves, `WRITE` calls — and its permissions come from the topology
//! row looked up by IMAGE NAME (`crates/core/topology/src/builder.rs`). One image
//! has one row and one seccomp profile, so one image has one role. The first
//! version of stage 2b put this serve loop inside `uhello` and let it serve or
//! not depending on how it was started; that does not work, for a reason worth
//! writing down because it is not visible in the syscall's signature:
//!
//! **`SYS_IPC_FAST_ACCEPT` (110) blocks, and there is no non-blocking form.**
//! Its `None` arm calls `task_block(WaitReason::FastIpcServer(tid))`, and the
//! only thing that releases that waiter is a client calling THIS server. A
//! task that accepts when nobody will ever call it is wedged for good. Run as
//! autorun, `uhello` held `WRITE` — it was nobody's server — and it hung
//! there, **invisibly**: the `userspace: minimal Rust ELF` gate row asserts the
//! seccomp-refusal line, which is printed before the serve loop, so the row
//! stayed green over a task that never exited. Measured 2026-09-20: the
//! autorun log ends at the refusal line and the "served 0 exchange(s)" line
//! never appears.
//!
//! So the role cannot be discovered at runtime and must not be guessed. It is
//! declared, once, by which image the topology grants `READ` to — this one.
//!
//! # Exactly one exchange, and why that is not a limitation here
//!
//! This program issues **one** accept and exits. Not a bounded loop: a second
//! accept would block on a second call that `abitest` never makes, which is
//! the same wedge in a new place. One accept is safe in either interleaving —
//! if the call arrives first the kernel hands it over with no block at all,
//! and if this program gets there first the call wakes it.
//!
//! A real server loops forever and that is correct for a real server. The
//! thing neither shape can express today is a server that polls, times out or
//! shuts down, because that needs a non-blocking accept the ABI does not have.
//! That gap is known; it is not needed
//! to demonstrate capability-addressed IPC, so it is not closed here.

#![no_std]
#![no_main]

use azos_libsys as sys;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    sys::println(b"[epsrv] endpoint.demo server running");

    match sys::fast_ipc_accept_req() {
        Some(req) => {
            if !req.delivered {
                // The kernel accepted an exchange and did NOT hand over the
                // payload. Distinguished from "wrong words" on purpose — see
                // `FastRequest::delivered`.
                sys::println(b"[epsrv] FAILED: accept without a delivered payload");
                sys::exit(1);
            }
            // RFC-0040 gap 2 stage 4 — the capability the client MOVED here.
            //
            // The move happened in the client's own trap, before this
            // exchange was ever `Pending`, so this handle is already in this
            // task's table: reading it claims nothing and dropping it would
            // leak authority rather than decline it.
            //
            // **Closing it is a POSITIVE proof.** `close_typed` on a handle
            // this task does not hold answers `-ECAPSTALE`, so a success here
            // cannot be produced by a capability that never arrived — which
            // "no error was reported" could.
            if req.moved_cap == 0 {
                sys::println(b"[epsrv] FAILED: no capability moved with the request");
                sys::exit(1);
            }
            if sys::close_typed(req.moved_cap) < 0 {
                sys::println(b"[epsrv] FAILED: the moved capability does not resolve here");
                sys::exit(1);
            }
            sys::println(b"[epsrv] closed the moved Cap<Socket>: it resolves in MY table");

            let reply = [req.words[0].wrapping_add(1), 0, 0, 0];
            if sys::fast_ipc_reply(req.handle, reply) < 0 {
                sys::println(b"[epsrv] FAILED: reply refused");
                sys::exit(1);
            }
            sys::println(b"[epsrv] served 1 exchange");
            sys::exit(0);
        }
        None => {
            // Reachable two ways, and they are worth telling apart when this
            // line shows up: the seccomp profile refused 110 (then this
            // program is not the server the topology thinks it is), or the
            // kernel's bounded spurious-wake retry ran out. Neither is a
            // served exchange, so both are a failure of this image's one job.
            sys::println(b"[epsrv] FAILED: accept returned no request");
            sys::exit(1);
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::println(b"[epsrv] PANIC");
    sys::exit(101);
}

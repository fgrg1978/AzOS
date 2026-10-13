// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The deadline a call carries (`MsgDesc::deadline`, `MsgDesc::clock_id`),
//! checked before the call is queued.
//!
//! Pure on purpose: the caller passes the monotonic clock's reading, so the
//! rule runs the same in the kernel (`ipc_v2::sys_ipc_call_v2`) and in the
//! host suite (`tests/host/syscall-tests`). It depends on `azos_abi` and
//! `azos_decision` only.
//!
//! The rule, in the order it is applied:
//!
//! 1. A reserved word that is not 0, or a `clock_id` other than
//!    [`ClockId::MONO`]: `-EINVAL`. The kernel serves one clock; a caller
//!    that names another is refused rather than read on the wrong one.
//! 2. A deadline other than 0 that is at or before `now_mono_ns`:
//!    `-EDEADLINE`, and one `decision` record
//!    ([`Rule::DeadlineExpired`](azos_decision::Rule), verdict Refuse, subject
//!    the caller's tid, numbers `[deadline, now, clock_id]`). The call has not
//!    been queued and no capability has moved, so there is nothing to undo.
//!
//! 3. A capability entry whose `expiry_ns` is other than 0 and at or before
//!    `now_mono_ns` ([`check_caps`]): the same refusal, with `Rule::DeadlineExpired`
//!    and the numbers `[expiry, now, handle]`. The copy would have been born
//!    expired; nothing has moved. A later expiry is not checked here: the
//!    kernel takes the earlier of it and the sender's own when it derives the
//!    receiver's copy (`azos_ipc::cap::narrow_warrant`).
//!
//! The server reads the same fields in the descriptor it receives; that is
//! the inheritance hook, not a check made here.

use azos_abi::error::Errno;
use azos_abi::ipc_msg::MsgDesc;
use azos_abi::time::ClockId;
use azos_decision::{Rule, Verdict};

/// `Ok` when the call may proceed, else the negative code to return.
pub fn check(d: &MsgDesc, now_mono_ns: u64, caller_tid: u32) -> Result<(), i64> {
    if d._pad != 0 || !ClockId(d.clock_id).is_mono() {
        return Err(Errno::EINVAL.to_syscall_ret());
    }
    if d.deadline != 0 && d.deadline <= now_mono_ns {
        azos_decision::record(
            Rule::DeadlineExpired,
            Verdict::Refuse,
            caller_tid,
            [d.deadline, now_mono_ns, d.clock_id as u64],
        );
        return Err(Errno::EDEADLINE.to_syscall_ret());
    }
    Ok(())
}

/// The `reason` of the `cap-denial` record of a real-time caller on a proxy
/// endpoint (after `CapError::code`'s 1 to 6, which it continues).
pub const DENIAL_REALTIME_ON_PROXY: u64 = 7;

/// `Ok` when a call to an endpoint that is (`is_proxy`) or is not a proxy may
/// proceed for a caller of scheduler class `class_raw()`, else `-ERTPROXY` and
/// one `cap-denial` record. A proxy is a service on another node: the call
/// takes as long as the link does, which a reservation cannot promise, so a
/// real-time caller (a class at or below `RT_CLASS_MAX`) is refused before
/// anything is queued. The topology refuses the same pairing at admission
/// (`neverallow`); this is the task that became real-time after it.
pub fn check_proxy(is_proxy: bool, class_raw: impl FnOnce() -> u8, caller_tid: u32) -> Result<(), i64> {
    // The class is read only for a proxy: an ordinary call pays one flag.
    if is_proxy && class_raw() <= crate::handlers::RT_CLASS_MAX {
        azos_decision::record(
            Rule::CapDenial,
            Verdict::Deny,
            caller_tid,
            [azos_abi::cap::CapKind::Endpoint.denial_code() as u64, DENIAL_REALTIME_ON_PROXY, 0],
        );
        return Err(Errno::ERTPROXY.to_syscall_ret());
    }
    Ok(())
}

/// `Ok` when no capability entry of `d` (a message the task sends, call or
/// reply) carries a deadline that has already passed, else `-EDEADLINE` and
/// one `decision` record. Only the first `d.n_caps` entries are read.
pub fn check_caps(d: &MsgDesc, now_mono_ns: u64, sender_tid: u32) -> Result<(), i64> {
    for c in d.caps.iter().take(d.n_caps as usize) {
        if c.expiry_ns != 0 && c.expiry_ns <= now_mono_ns {
            azos_decision::record(
                Rule::DeadlineExpired,
                Verdict::Refuse,
                sender_tid,
                [c.expiry_ns, now_mono_ns, c.handle as u64],
            );
            return Err(Errno::EDEADLINE.to_syscall_ret());
        }
    }
    Ok(())
}

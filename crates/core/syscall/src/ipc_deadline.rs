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
//! 1. A provenance label with a reserved bit (`MsgDesc::label` outside
//!    `LABEL_KNOWN`), or a `clock_id` other than
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
//! 4. A deadline the server's scheduling context cannot meet ([`admit`]):
//!    `-EADMIT`, with a counter-offer receipt. The call is still not queued.
//!
//! The server reads the same fields in the descriptor it receives (the
//! inheritance hook): a server that calls on with the deadline it was given
//! is admitted by the next server against the time left then, so a chain of
//! calls is refused at the first hop that cannot finish in time.
//!
//! # Admission against the server's SC (rule 4)
//!
//! What the server's scheduling context promises a call ([`ServerSc`]):
//!
//! * **Reserved** (its own EDF + CBS reservation, an *active* server): its
//!   budget is served within its relative deadline of a release, so the call
//!   is admitted when that relative deadline fits the time left. Refused, the
//!   counter-offer is the earliest deadline it can meet, `now + d`.
//! * **Passive** (no reservation, a per-call budget `c` from its topology
//!   row's `call_budget_us`): it runs on the caller's reservation (seL4 MCS
//!   passive servers; `azos_sched::rt` proxy execution). `c` must fit the
//!   time left (else the offer is `now + c`); a caller that lends a
//!   reservation ([`Lent`]) must have `c` of budget left (else the offer is
//!   the budget, `c`) and a reservation deadline at or before the call's
//!   (else the offer is that deadline: its budget is promised only by then).
//!   A caller with no reservation lends nothing, and only the time is
//!   checked: the call runs best effort, at the caller's priority.
//! * **None**: nothing is promised, nothing is checked (best effort).
//!
//! The rule is [`admit_rule`], pure; [`admit`] adds the receipt: one
//! `call-admission` decision record per refusal (only refusals: an admitted
//! call writes nothing, and a call with no deadline is never asked).
//! Canary `ipc-admit-canary`: every call is admitted.

use azos_abi::error::Errno;
use azos_abi::ipc_msg::MsgDesc;
use azos_abi::time::ClockId;
use azos_decision::{Rule, Verdict};

/// `Ok` when the call may proceed, else the negative code to return.
pub fn check(d: &MsgDesc, now_mono_ns: u64, caller_tid: u32) -> Result<(), i64> {
    if d.label & !azos_abi::ipc_msg::LABEL_KNOWN != 0 || !ClockId(d.clock_id).is_mono() {
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

/// What a server's scheduling context promises a call, in nanoseconds (see
/// the module doc).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerSc {
    /// No time parameters: nothing is promised.
    None,
    /// Its own reservation: `budget` of work within `deadline` (relative) of
    /// a release.
    Reserved { budget: u64, deadline: u64 },
    /// No reservation of its own, `call_budget` of work per call, run on
    /// the caller's reservation.
    Passive { call_budget: u64 },
}

/// The reservation a caller lends the call: the budget it has left and the
/// absolute deadline of its current server period, nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lent {
    pub budget: u64,
    pub deadline: u64,
}

/// A counter-offer: the nearest deadline or budget the server would admit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alt {
    /// An absolute deadline, nanoseconds on `MONO`.
    Deadline(u64),
    /// A budget the caller must lend, nanoseconds.
    Budget(u64),
}

impl Alt {
    /// The kind word of the descriptor and the record: 1 deadline, 2 budget.
    pub const fn kind(self) -> u64 {
        match self {
            Alt::Deadline(_) => ALT_DEADLINE,
            Alt::Budget(_) => ALT_BUDGET,
        }
    }

    /// The offered value: absolute ns for a deadline, us for a budget (the
    /// unit of the row it is compared with, `call_budget_us`).
    pub const fn value(self) -> u64 {
        match self {
            Alt::Deadline(ns) => ns,
            Alt::Budget(ns) => ns.div_ceil(1_000),
        }
    }
}

/// [`Alt::kind`] of a deadline offer.
pub const ALT_DEADLINE: u64 = 1;
/// [`Alt::kind`] of a budget offer.
pub const ALT_BUDGET: u64 = 2;

/// A refused call: the receipt (the `call-admission` record's id, 0 when
/// this build stores records nowhere) and the counter-offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused {
    pub receipt: u64,
    pub alt: Alt,
}

/// Where a refusal's counter-offer is in the descriptor `SYS_IPC_CALL_V2`
/// writes back with `-EADMIT`: `words[0]` the receipt, `words[1]` the kind
/// ([`ALT_DEADLINE`], [`ALT_BUDGET`]), `words[2]` the value; `deadline` is
/// the offered deadline (the call's own for a budget offer): a caller that
/// takes the offer copies it into its own request and calls again.
pub const REFUSED_WORDS: u8 = 3;

/// Canary `ipc-admit-canary`: every call is admitted.
const ADMIT_ON: bool = !cfg!(feature = "ipc-admit-canary");

/// Rule 4 alone (module doc): `Ok` when the server's SC can finish a call
/// with absolute `deadline` (0 = none) issued at `now`, else the nearest
/// admissible alternative. `lent` is the caller's reservation, if it has one.
pub const fn admit_rule(now: u64, deadline: u64, server: ServerSc, lent: Option<Lent>) -> Result<(), Alt> {
    if deadline == 0 || !ADMIT_ON {
        return Ok(());
    }
    let left = deadline.saturating_sub(now);
    match server {
        ServerSc::None => Ok(()),
        ServerSc::Reserved { deadline: d, .. } => {
            if d <= left { Ok(()) } else { Err(Alt::Deadline(now.saturating_add(d))) }
        }
        ServerSc::Passive { call_budget: c } => {
            if c > left {
                return Err(Alt::Deadline(now.saturating_add(c)));
            }
            match lent {
                None => Ok(()),
                Some(l) if l.budget < c => Err(Alt::Budget(c)),
                Some(l) if l.deadline > deadline => Err(Alt::Deadline(l.deadline)),
                Some(_) => Ok(()),
            }
        }
    }
}

/// Rule 4 with its receipt: [`admit_rule`], and on a refusal one
/// `call-admission` record (subject the caller, numbers `[deadline, alt
/// value, kind << 32 | server_tid]`) whose id is the receipt.
pub fn admit(
    now: u64, deadline: u64, server: ServerSc, lent: Option<Lent>, caller_tid: u32, server_tid: u32,
) -> Result<(), Refused> {
    match admit_rule(now, deadline, server, lent) {
        Ok(()) => Ok(()),
        Err(alt) => {
            let receipt = azos_decision::record_receipt(
                Rule::CallAdmission,
                Verdict::Refuse,
                caller_tid,
                [deadline, alt.value(), alt.kind() << 32 | server_tid as u64],
            );
            Err(Refused { receipt, alt })
        }
    }
}

/// The descriptor a refused call reads back: `d` with the counter-offer of
/// `r` in it (see [`REFUSED_WORDS`]). No capability: none moved.
pub fn refused_desc(d: &MsgDesc, r: Refused) -> MsgDesc {
    let mut out = MsgDesc { version: d.version, deadline: d.deadline, clock_id: d.clock_id, ..MsgDesc::default() };
    out.n_words = REFUSED_WORDS;
    out.words[0] = r.receipt;
    out.words[1] = r.alt.kind();
    out.words[2] = r.alt.value();
    if let Alt::Deadline(ns) = r.alt {
        out.deadline = ns;
    }
    out
}

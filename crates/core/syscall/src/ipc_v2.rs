// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ABI v2 of the call (wave 15 N11b): `SYS_IPC_CALL_V2`,
//! `SYS_IPC_ACCEPT_V2`, `SYS_IPC_REPLY_V2`,
//! `SYS_IPC_REPLY_DELEGATE` and `SYS_CAP_DERIVE`.
//!
//! The v1 arms in `dispatch.rs` (582, 110, 109, 580) are not touched: these
//! arms sit in the slow match beside them and share only the call queue
//! (`azos_ipc::fastcall`), so a v2 server may accept a v1 call (no
//! `MSG_BADGED`). A v1 server may not accept a v2 call (owner decision
//! 10-10, N11c): its accept refuses it, the call ends `-EV1ACCEPT`, and the
//! caller takes back every capability it moved. The descriptor also
//! carries the caller's deadline (see `ipc_deadline`): a call whose deadline has
//! passed is refused before it is queued, and the server reads the deadline in
//! what it accepts. Each capability entry carries its own `expiry_ns`, the
//! deadline of the receiver's copy (an entry born expired is refused the same
//! way; the kernel takes the earlier of it and the sender's own). The message is one `MsgDesc` in the caller's memory,
//! read and written with the checked user copies; nothing comes back in
//! registers but `a0`, so libsys uses its plain syscall helpers.

use azos_abi::cap::{CapHandle, CapPerms};
use azos_abi::error::Errno;
use azos_abi::ipc_msg::{CapDesc, MsgDesc, CAP_MODE_DUP, CAP_MODE_MOVE, MSG_BADGED, MSG_KEEP, MSG_VERSION};
use azos_ipc::cap_store::{self, CapXfer};
use azos_ipc::fastcall::{self, Collected, Delegated, Payload, V2_CAPS, V2_WORDS, WORDS};
use azos_ipc::fastcall::NO_DONEE;

/// One code for every refusal that would otherwise report on a table the
/// caller does not hold (same rule as the v1 call arm).
const E_PERM: i64 = -1;
/// The call is over (same value as the v1 reply's).
const E_OVER: i64 = -2;
/// Not the holder of an unanswered call's warrant (same value as the v1
/// reply-accept's "any other refusal").
const E_NOT_HOLDER: i64 = -3;

fn einval() -> i64 {
    Errno::EINVAL.to_syscall_ret()
}

fn efault() -> i64 {
    Errno::EFAULT.to_syscall_ret()
}

/// Runtime canary `ipc-v2-as-v1` (boot flag): the v2 accept reads every
/// call as a v1 call (four words, no badge, one capability), so the ktest
/// `ipc_v2_call_carries_caps_words_and_badge` must fail.
static CANARY_AS_V1: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Arm the `ipc-v2-as-v1` canary (boot only).
pub fn canary_as_v1() {
    CANARY_AS_V1.store(true, core::sync::atomic::Ordering::Relaxed);
}

/// Bytes of a descriptor in user memory: the whole struct, always.
const DESC_BYTES: usize = core::mem::size_of::<MsgDesc>();

/// The descriptor at `ptr`.
fn read_desc(ptr: u64) -> Option<MsgDesc> {
    let mut d = MsgDesc::default();
    azos_sched::copy_from_user(&mut d as *mut MsgDesc as *mut u8, ptr as usize, DESC_BYTES).then_some(d)
}

/// Write `d` at `ptr`.
fn write_desc(ptr: u64, d: &MsgDesc) -> bool {
    azos_sched::copy_to_user(ptr as usize, d as *const MsgDesc as *const u8, DESC_BYTES)
}

const NO_XFER: CapXfer = CapXfer::new(CapHandle(0), false);

/// The kernel's checks of a descriptor a task sends: its version, counts
/// within the Kconfig limits, no flag but `MSG_KEEP`, and each capability
/// entry well formed. The entries go to `xs`; how many.
fn xfers(d: &MsgDesc, now_ns: u64, sender_tid: u32, xs: &mut [CapXfer; V2_CAPS]) -> Result<usize, i64> {
    if d.version != MSG_VERSION
        || d.n_words as usize > V2_WORDS
        || d.n_caps as usize > V2_CAPS
        || d.flags & !MSG_KEEP != 0
    {
        return Err(einval());
    }
    let n = d.n_caps as usize;
    // A copy born expired is refused before anything moves.
    crate::ipc_deadline::check_caps(d, now_ns, sender_tid)?;
    for (x, c) in xs.iter_mut().zip(d.caps.iter()).take(n) {
        let dup = match c.mode {
            CAP_MODE_MOVE => false,
            CAP_MODE_DUP => true,
            _ => return Err(einval()),
        };
        if c._pad != 0 || c.rights & !(CapPerms::ALL.bits() as u16) != 0 {
            return Err(einval());
        }
        let rights = (c.rights != 0).then(|| CapPerms::from_bits_truncate(c.rights as u8));
        *x = CapXfer { rights, expiry_ns: c.expiry_ns, ..CapXfer::new(CapHandle(c.handle), dup) };
    }
    Ok(n)
}

/// The payload of `d` with the receiver's handles `got`.
fn payload_of(d: &MsgDesc, got: &[CapHandle]) -> Payload {
    let mut p = Payload::EMPTY;
    p.n_words = d.n_words;
    p.n_caps = got.len() as u8;
    for (w, s) in p.words.iter_mut().zip(d.words.iter()).take(d.n_words as usize) {
        *w = *s;
    }
    for (c, h) in p.caps.iter_mut().zip(got.iter()) {
        *c = h.0;
    }
    p
}

/// The v1 words of payload `p`: its first four (0 past `n_words`).
fn first_words(p: &Payload) -> [u64; WORDS] {
    let mut w = [0u64; WORDS];
    for (k, d) in w.iter_mut().enumerate().take(p.n_words as usize) {
        *d = p.words[k];
    }
    w
}

/// The descriptor a receiver reads for payload `p`; `badge` `Some` sets
/// `MSG_BADGED`.
fn desc_of(p: &Payload, badge: Option<u32>) -> MsgDesc {
    let mut d = MsgDesc { version: MSG_VERSION, n_words: p.n_words, n_caps: p.n_caps, ..MsgDesc::default() };
    for (w, s) in d.words.iter_mut().zip(p.words.iter()).take(p.n_words as usize) {
        *w = *s;
    }
    for (c, h) in d.caps.iter_mut().zip(p.caps.iter()).take(p.n_caps as usize) {
        *c = CapDesc { handle: *h, mode: CAP_MODE_MOVE, _pad: 0, rights: 0, expiry_ns: 0 };
    }
    d.deadline = p.deadline;
    d.clock_id = p.clock_id;
    if let Some(b) = badge {
        d.flags |= MSG_BADGED;
        d.badge = b as u64;
    }
    d
}

/// The descriptor of a v1 message: four words, and the one capability a v1
/// call moves (`cap`, 0 for none).
fn desc_of_v1(words: [u64; WORDS], cap: u32) -> MsgDesc {
    let mut p = Payload::EMPTY;
    p.n_words = WORDS.min(V2_WORDS) as u8;
    for (d, s) in p.words.iter_mut().zip(words.iter()) {
        *d = *s;
    }
    if cap != 0 && V2_CAPS > 0 {
        p.n_caps = 1;
        p.caps[0] = cap;
    }
    desc_of(&p, None)
}

/// Undo the transfer of `xs` from `to` to `from` (`hs`: the handles they
/// took in `from`'s table) after its message went nowhere: a MOVE entry goes
/// back to `to`, a DUP entry's copy is destroyed (`to` kept its own handle),
/// and one that cannot go back is destroyed and reported, never left in
/// `from`'s table (`cap_store::undo_move_caps`).
fn give_back(from: u32, to: u32, xs: &[CapXfer], hs: &[CapHandle]) {
    if hs.is_empty() {
        return;
    }
    let lost = cap_store::undo_move_caps(to, from, xs, hs);
    if lost != 0 {
        azos_drv_sys::kerr!("[SAFETY_CAP_STRANDED] v2: tid={} -> tid={} {} cap(s) not given back, revoked", from, to, lost);
    }
}

/// `SYS_IPC_CALL_V2` — `a0 = Cap<Endpoint>`, `a1 = *mut MsgDesc`. See the
/// number's doc in `azos_abi::syscall_nr`.
pub fn sys_ipc_call_v2(ep_raw: u64, msg_ptr: u64) -> i64 {
    let Some(d) = read_desc(msg_ptr) else { return efault() };
    let mut out = MsgDesc::default();
    match call_v2(ep_raw, &d, &mut out) {
        0 => if write_desc(msg_ptr, &out) { 0 } else { efault() },
        e => e,
    }
}

/// The call of `SYS_IPC_CALL_V2` on a request in kernel memory: the middle of
/// the syscall, which only reads `d` from and writes `out` to the caller's
/// memory around it (`sys_ipc_call_v2`), and the one body the kernel's own
/// calls to a task-served endpoint use (`crate::kcall`). 0 when answered, with
/// the answer in `*out`; else the call's negative code, `*out` untouched.
///
/// The caller is the running task, whatever its ring: it needs a `WRITE`
/// capability on the endpoint in its own table, blocks until the server
/// replies, and must not hold a spinlock while it does
/// (`crate::kcall::call` checks that before it gets here).
pub(crate) fn call_v2(ep_raw: u64, d: &MsgDesc, out: &mut MsgDesc) -> i64 {
    let (caller_idx, caller_tid) = azos_sched::current_task_slot().unwrap_or((usize::MAX, 0));
    // A deadline already past (or a clock this kernel does not serve), or a
    // capability entry born expired, is refused before anything moves or is
    // queued: nothing to give back.
    let now = azos_abi::time::ticks_to_ns(azos_drv_sys::timebase::now(), azos_drv_sys::timebase::TIMER_FREQ);
    let mut xs = [NO_XFER; V2_CAPS];
    let nx = match xfers(d, now, caller_tid, &mut xs) {
        Ok(n) => n,
        Err(e) => return e,
    };
    if let Err(e) = crate::ipc_deadline::check(d, now, caller_tid) {
        return e;
    }
    let Some(dest) = crate::dispatch::resolve_endpoint_dest(caller_idx, caller_tid, ep_raw) else { return E_PERM };
    // A proxy endpoint is a service on another node: a real-time caller is
    // refused before anything is queued (`ipc_deadline::check_proxy`).
    if let Err(e) = crate::ipc_deadline::check_proxy(
        azos_ipc::endpoint::is_proxy(&dest),
        || azos_sched::current_sched_params().1,
        caller_tid,
    ) {
        return e;
    }
    // An interface the kernel hosts is served here, on the caller's own
    // stack: no queue, no task switch.
    if let Some(key) = azos_ipc::endpoint::host_key(dest.owner) {
        return call_kernel_hosted(key, caller_tid, ep_raw, d, nx, out);
    }
    // The badge of the capability the call goes through: its slot's
    // extension word (0 unbadged, and always 0 without Kconfig CAP_SLOT_EXT).
    let badge = cap_store::with_table(caller_tid, |t| t.ext_of(CapHandle(ep_raw as u32)))
        .flatten()
        .map_or(0, |e| e.badge);
    let server = dest.owner;
    // The capabilities move BEFORE the call is published, for the reason the
    // v1 arm gives: a server woken on it may accept at once on another hart.
    let mut got = [CapHandle(0); V2_CAPS];
    if nx > 0 && cap_store::move_caps(caller_tid, server, &xs[..nx], d.flags & MSG_KEEP != 0, &mut got[..nx]).is_err() {
        return E_PERM;
    }
    // A MemObj capability that moved took the caller's mapping of it along.
    if nx > 0 {
        crate::ipc_handlers::reap_moved_windows();
    }
    let got = &got[..nx];
    let mut p = payload_of(d, got);
    // The deadline travels with the message: the server reads it in the
    // descriptor it receives (inheritance).
    p.deadline = d.deadline;
    p.clock_id = d.clock_id;
    // The first capability fills the v1 record's `moved_cap`, which the exit
    // and drain paths revoke; a v1 accept refuses the call (N11c).
    let moved_cap = got.first().map_or(0, |h| h.0);
    let Some(handle) =
        fastcall::call_v2_msg(caller_idx, caller_tid, dest, first_words(&p), moved_cap, false, badge, &p)
    else {
        give_back(server, caller_tid, &xs[..nx], got);
        return E_PERM;
    };

    // The wait: the v1 arm's, without its census (same bound, same rule for
    // spurious wakes; a forced kill spends the turns without blocking).
    let mut answer: Option<[u64; WORDS]> = None;
    let mut result = E_PERM;
    let mut completed = false;
    for turn in 0..azos_limits::IPC_CALL_WAKE_RETRIES as u32 {
        if turn == 0 {
            azos_sched::scheduler::fast_ipc_call_handoff(server, handle);
        } else {
            azos_sched::task_block_unless_killed(azos_sched::WaitReason::FastIpcClient(handle));
        }
        match fastcall::collect(handle, caller_tid) {
            Collected::Reply(w, donee) => {
                if donee != NO_DONEE {
                    azos_sched::return_donation(donee);
                }
                answer = Some(w);
                break;
            }
            Collected::Done(code, donee) => {
                if donee != NO_DONEE {
                    azos_sched::return_donation(donee);
                }
                // Refused by a v1 accept: the server never saw the call, so
                // every capability it carried comes back, on the path of a
                // call withdrawn before it was taken (a caller that exits
                // before this point has them revoked by its exit sweep).
                // (`-EPEERDIED` and `-EREVOKED` keep their rule: every one
                // the queued call moved is revoked.)
                if code == i64::from(azos_ipc::ep_queue::V1_ACCEPT) {
                    give_back(server, caller_tid, &xs[..nx], got);
                }
                result = code;
                completed = true;
                break;
            }
            Collected::Nothing => match fastcall::wait_state(handle, caller_tid) {
                azos_ipc::FastIpcWait::Waiting | azos_ipc::FastIpcWait::Ready => continue,
                azos_ipc::FastIpcWait::Gone => break,
            },
        }
    }
    if let Some(w) = answer {
        *out = match fastcall::take_reply(caller_idx, handle) {
            Some(rp) => desc_of(&rp, None),
            // A v1 reply (109/580): its four words are the whole answer.
            None => desc_of_v1(w, 0),
        };
        return 0;
    }
    if !completed {
        let a = fastcall::abandon(handle, caller_tid);
        if a.donee != NO_DONEE {
            azos_sched::return_donation(a.donee);
        }
        if a.was_queued {
            give_back(server, caller_tid, &xs[..nx], got);
        }
    }
    result
}

/// A v2 call to an endpoint the kernel hosts (`crate::khost`): decode, run the
/// interface's op for the capability's badge and rights, write the reply into `out`. A
/// request that carries capabilities is refused (`-EINVAL`: no kernel-hosted
/// interface takes one), and nothing moved before this point.
fn call_kernel_hosted(key: u16, caller_tid: u32, ep_raw: u64, d: &MsgDesc, n_caps: usize, out: &mut MsgDesc) -> i64 {
    if n_caps != 0 {
        return einval();
    }
    let Some(who) = u32::try_from(ep_raw).ok().and_then(|h| crate::khost::caller(caller_tid, h)) else {
        return E_PERM;
    };
    crate::khost::serve(key, &who, d, out);
    0
}

/// `SYS_IPC_ACCEPT_V2` — `a0 = *mut MsgDesc`. See the number's doc.
pub fn sys_ipc_accept_v2(msg_ptr: u64) -> i64 {
    // The buffer is checked before a call is taken, so an unwritable one
    // never strands an accepted call.
    if !write_desc(msg_ptr, &MsgDesc::default()) {
        return efault();
    }
    let (idx, tid) = azos_sched::current_task_slot().unwrap_or((usize::MAX, 0));
    let mut o = crate::dispatch::SyscallOut::new();
    let h = crate::dispatch::fast_ipc_accept_into_waking_as::<false>(&mut o, idx, tid, None, None, NO_DONEE);
    if h < 0 {
        return h;
    }
    let handle = h as u64;
    let v2 = if CANARY_AS_V1.load(core::sync::atomic::Ordering::Relaxed) {
        None
    } else {
        fastcall::accept_msg(handle, tid)
    };
    let d = match v2 {
        Some(p) => desc_of(&p, Some(fastcall::accept_badge(handle, tid).unwrap_or(0))),
        // A v1 call: `o` holds (caller, four words, moved capability).
        None => desc_of_v1([o.regs[1], o.regs[2], o.regs[3], o.regs[4]], o.regs[5] as u32),
    };
    if write_desc(msg_ptr, &d) { h } else { efault() }
}

/// `SYS_IPC_REPLY_V2` — `a0` = call handle, `a1 = *const MsgDesc`. See the
/// number's doc.
pub fn sys_ipc_reply_v2(handle: u64, msg_ptr: u64) -> i64 {
    let Some(d) = read_desc(msg_ptr) else { return efault() };
    let tid = azos_sched::current_task_tid();
    let now = azos_abi::time::ticks_to_ns(azos_drv_sys::timebase::now(), azos_drv_sys::timebase::TIMER_FREQ);
    let mut xs = [NO_XFER; V2_CAPS];
    let nx = match xfers(&d, now, tid, &mut xs) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let Some((caller, v2)) = fastcall::warrant_peer(handle, tid) else { return E_NOT_HOLDER };
    // A v1 caller collects four words and no capability.
    if !v2 && (nx > 0 || d.n_words as usize > WORDS) {
        return einval();
    }
    let mut got = [CapHandle(0); V2_CAPS];
    if nx > 0 && cap_store::move_caps(tid, caller, &xs[..nx], d.flags & MSG_KEEP != 0, &mut got[..nx]).is_err() {
        return E_PERM;
    }
    if nx > 0 {
        crate::ipc_handlers::reap_moved_windows();
    }
    let got = &got[..nx];
    let p = payload_of(&d, got);
    if v2 && !fastcall::stage_reply(handle, tid, &p) {
        give_back(caller, tid, &xs[..nx], got);
        return E_NOT_HOLDER;
    }
    match fastcall::reply_warrant(handle, tid, first_words(&p)) {
        azos_ipc::FastIpcReply::Woke { caller_tid, donee, .. } => {
            azos_sched::wait::wake_fast_ipc_client_tid(caller_tid, handle);
            if donee != NO_DONEE {
                azos_sched::return_donation(donee);
            }
            0
        }
        azos_ipc::FastIpcReply::Stale => {
            give_back(caller, tid, &xs[..nx], got);
            E_OVER
        }
        azos_ipc::FastIpcReply::Refused => {
            give_back(caller, tid, &xs[..nx], got);
            E_NOT_HOLDER
        }
    }
}

/// `SYS_IPC_REPLY_DELEGATE` — `a0` = call handle, `a1` = TID of a thread of
/// the caller's process. See the number's doc.
///
/// The rule `ep_queue::delegate` leaves to this call: the warrant stays in
/// the caller's process (its worker threads). Handing it to another process
/// is a capability transfer of a reply right, which is the warrant
/// foundation's (plan L4), not this call's.
pub fn sys_ipc_reply_delegate(handle: u64, to: u64) -> i64 {
    let tid = azos_sched::current_task_tid();
    let Ok(to) = u32::try_from(to) else { return Errno::EPERM.to_syscall_ret() };
    if to == 0
        || azos_sched::idx_for_tid(to).is_none()
        || azos_sched::group::proc_tid(to) != azos_sched::group::proc_tid(tid)
    {
        return Errno::EPERM.to_syscall_ret();
    }
    match fastcall::delegate(handle, tid, to) {
        Delegated::Moved => 0,
        Delegated::Stale => E_OVER,
        Delegated::Refused => E_NOT_HOLDER,
    }
}
